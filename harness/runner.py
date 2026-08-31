"""Shared execution and artifact lifecycle for gas benchmarks."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import difflib
import json
from pathlib import Path
import sys
import tempfile
from typing import Callable

from harness.fixture import Fixture, generate


Artifact = dict[str, object]


class Context:
    """Lazy inputs shared by benchmarks in one suite run."""

    def __init__(self) -> None:
        self._fixture: Fixture | None = None

    @property
    def fixture(self) -> Fixture:
        """Generate the real Scheme 3 fixture at most once."""
        if self._fixture is None:
            self._fixture = generate()
        return self._fixture


@dataclass(frozen=True)
class Benchmark:
    """A live collector plus presentation and artifact location."""

    name: str
    output: Path
    collect: Callable[[Context], Artifact]
    render: Callable[[Artifact], str]


def _committed(benchmark: Benchmark) -> Artifact:
    try:
        body = json.loads(benchmark.output.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read {benchmark.output}: {exc}") from exc
    if not isinstance(body, dict):
        raise RuntimeError(f"{benchmark.output} is not a JSON object")
    return body


def _serialized(artifact: Artifact) -> str:
    return json.dumps(artifact, indent=2) + "\n"


def _difference(benchmark: Benchmark, committed: Artifact, live: Artifact) -> str:
    return "\n".join(
        difflib.unified_diff(
            _serialized(committed).splitlines(),
            _serialized(live).splitlines(),
            fromfile=str(benchmark.output),
            tofile=f"{benchmark.name} (live)",
            lineterm="",
        )
    )


def _write(benchmark: Benchmark, artifact: Artifact) -> None:
    temporary_path: Path | None = None
    mode = (
        benchmark.output.stat().st_mode & 0o777
        if benchmark.output.exists()
        else 0o644
    )
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=benchmark.output.parent,
            prefix=f".{benchmark.output.name}.",
            delete=False,
        ) as temporary:
            temporary.write(_serialized(artifact))
            temporary_path = Path(temporary.name)
        temporary_path.chmod(mode)
        temporary_path.replace(benchmark.output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def execute(
    benchmark: Benchmark,
    context: Context,
    *,
    check: bool,
    update: bool,
) -> bool:
    """Run one live benchmark and optionally compare or update its artifact."""
    try:
        artifact = benchmark.collect(context)
        committed = _committed(benchmark) if check else None
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"FAIL {benchmark.name}: {exc}", file=sys.stderr)
        return False

    print(benchmark.render(artifact))
    if check and committed != artifact:
        print(f"\nFAIL {benchmark.name}: committed artifact is stale", file=sys.stderr)
        print(_difference(benchmark, committed, artifact), file=sys.stderr)
        return False
    if check:
        print("\ncommitted artifact: OK")
    elif update:
        try:
            _write(benchmark, artifact)
        except OSError as exc:
            print(
                f"\nFAIL {benchmark.name}: cannot write {benchmark.output}: {exc}",
                file=sys.stderr,
            )
            return False
        print(f"\nwrote {benchmark.output}")
    return True


def parse_arguments(argv: list[str] | None, *, targets: bool) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    if targets:
        parser.add_argument(
            "target",
            nargs="?",
            default="all",
            choices=("all", "announcement", "registration", "payment"),
        )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check", action="store_true", help="compare with committed artifacts"
    )
    mode.add_argument(
        "--update", action="store_true", help="rewrite committed artifacts"
    )
    return parser.parse_args(argv)


def main_one(benchmark: Benchmark, argv: list[str] | None = None) -> int:
    """CLI for a per-benchmark entry point."""
    args = parse_arguments(argv, targets=False)
    return 0 if execute(
        benchmark, Context(), check=args.check, update=args.update
    ) else 1
