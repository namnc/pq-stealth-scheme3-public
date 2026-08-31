#!/usr/bin/env python3
"""Run the live gas benchmark suite."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.announcement.measure import BENCHMARK as ANNOUNCEMENT
from harness.payment.measure import BENCHMARK as PAYMENT
from harness.registration.measure import BENCHMARK as REGISTRATION
from harness.runner import Context, execute, parse_arguments


BENCHMARKS = {
    benchmark.name: benchmark
    for benchmark in (ANNOUNCEMENT, REGISTRATION, PAYMENT)
}


def main() -> int:
    args = parse_arguments(None, targets=True)
    selected = (
        BENCHMARKS.values()
        if args.target == "all"
        else [BENCHMARKS[args.target]]
    )
    context = Context()
    ok = True
    for index, benchmark in enumerate(selected):
        if index:
            print()
        ok = execute(
            benchmark, context, check=args.check, update=args.update
        ) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
