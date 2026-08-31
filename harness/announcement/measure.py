#!/usr/bin/env python3
"""Live ERC-5564 announcement gas benchmark."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.erc5564 import (  # noqa: E402
    ANNOUNCER,
    ANNOUNCER_SHA256,
    install_announcer,
    send_announcement,
)
from harness.eip7623 import (  # noqa: E402
    INTRINSIC,
    STANDARD_TOKEN_GAS,
    all_nonzero_payload_bound,
    floor_binds,
    floor_gas,
    tokens,
)
from harness.evm import Anvil, HARDFORK, gas_used  # noqa: E402
from harness.runner import Benchmark, Context, main_one  # noqa: E402
from tools import derive_sizes  # noqa: E402


OUT = Path(__file__).resolve().parent / "measured.json"
FIXED_STEALTH = bytes.fromhex("6dbb67f21b650304b5f459833188f52db07c2b43")


@dataclass(frozen=True)
class Case:
    name: str
    scheme_id: int
    kind: str
    stealth_address: bytes
    epk: bytes
    metadata: bytes


def _nonzero(length: int) -> bytes:
    return bytes(1 + index % 255 for index in range(length))


def _observation(receipt: dict, calldata: str) -> dict[str, int]:
    raw = bytes.fromhex(calldata.removeprefix("0x"))
    return {
        "calldata_bytes": len(raw),
        "zero_bytes": raw.count(0),
        "gas_used": gas_used(receipt),
    }


def _send(url: str, case: Case, *, zero_payload: bool = False) -> dict[str, int]:
    epk = bytes(len(case.epk)) if zero_payload else case.epk
    metadata = bytes(len(case.metadata)) if zero_payload else case.metadata
    receipt, calldata = send_announcement(
        url,
        case.scheme_id,
        "0x" + case.stealth_address.hex(),
        "0x" + epk.hex(),
        "0x" + metadata.hex(),
    )
    return _observation(receipt, calldata)


def _cases(context: Context) -> list[Case]:
    """One measured row per schemeId.

    schemeId 3 announces the real fixture. schemeId 1 has no fixture -- ERC-5564 does not
    say what a classical announcement's bytes are, so there is nothing to derive one from --
    and its row is therefore CONSTRUCTED: a payload of the right widths carrying no zero
    byte. It is a reference point for the ratio, not a sample of anything.
    """
    fixture = context.fixture
    epk_bytes, metadata_bytes = derive_sizes.SHAPES["schemeId 3 announcement"]
    if (len(fixture.epk), len(fixture.metadata)) != (epk_bytes, metadata_bytes):
        raise RuntimeError("fixture announcement does not match Section 6's wire table")
    return [
        Case(
            "classical_reference",
            1,
            "constructed_reference",
            FIXED_STEALTH,
            _nonzero(33),
            _nonzero(1),
        ),
        Case(
            "scheme3_real_sample",
            3,
            "real_sample",
            fixture.stealth_address,
            fixture.epk,
            fixture.metadata,
        ),
    ]


def collect(context: Context) -> dict:
    """Run each case and a same-shape all-zero payload probe."""
    cases = _cases(context)
    results = []
    diagnostics = []
    with Anvil() as node:
        install_announcer(node.url)
        for case in cases:
            transaction = _send(node.url, case)
            probe = _send(node.url, case, zero_payload=True)
            payload_zero_bytes = case.epk.count(0) + case.metadata.count(0)
            results.append(
                {
                    "name": case.name,
                    "scheme_id": case.scheme_id,
                    "kind": case.kind,
                    "epk_bytes": len(case.epk),
                    "metadata_bytes": len(case.metadata),
                    "payload_zero_bytes": payload_zero_bytes,
                    # Derived from the row beside it, never sent. See harness/eip7623.py.
                    "upper_bound_gas": all_nonzero_payload_bound(
                        transaction, payload_zero_bytes
                    ),
                    "transaction": transaction,
                }
            )
            diagnostics.append(
                {
                    "name": f"{case.name}_execution_probe",
                    "for_case": case.name,
                    "kind": "zero_dynamic_fields_probe",
                    "transaction": probe,
                }
            )
    _assert_accounting(results, diagnostics)
    return {
        "schema_version": 1,
        "benchmark": "announcement",
        "environment": {
            "hardfork": HARDFORK,
            "contract_address": ANNOUNCER,
            "contract_code_sha256": ANNOUNCER_SHA256,
        },
        "fixture": {
            "name": context.fixture.name,
            "sha256": context.fixture.sha256,
        },
        "results": results,
        "diagnostics": diagnostics,
    }


def _calldata_bytes(epk_bytes: int, metadata_bytes: int) -> int:
    padded_epk = 32 * ((epk_bytes + 31) // 32)
    padded_metadata = 32 * ((metadata_bytes + 31) // 32)
    return 4 + 4 * 32 + 32 + padded_epk + 32 + padded_metadata


def _assert_accounting(results: list[dict], diagnostics: list[dict]) -> None:
    """Assert ABI lengths and EIP-7623 directly over the live observations."""
    probes = {probe["for_case"]: probe["transaction"] for probe in diagnostics}
    for result in results:
        primary = result["transaction"]
        probe = probes[result["name"]]
        expected_calldata = _calldata_bytes(
            result["epk_bytes"], result["metadata_bytes"]
        )
        if primary["calldata_bytes"] != expected_calldata:
            raise RuntimeError(f"{result['name']}: wrong primary calldata length")
        if probe["calldata_bytes"] != expected_calldata:
            raise RuntimeError(f"{result['name']}: wrong diagnostic calldata length")

        probe_tokens = tokens(probe)
        execution = probe["gas_used"] - INTRINSIC - STANDARD_TOKEN_GAS * probe_tokens
        if execution < 0 or floor_binds(probe):
            raise RuntimeError(
                f"{result['name']}: diagnostic does not expose execution"
            )
        primary_tokens = tokens(primary)
        predicted = max(
            INTRINSIC + STANDARD_TOKEN_GAS * primary_tokens + execution,
            floor_gas(primary_tokens),
        )
        if primary["gas_used"] != predicted:
            raise RuntimeError(
                f"{result['name']}: EIP-7623 predicts {predicted}, "
                f"receipt says {primary['gas_used']}"
            )


def render(artifact: dict) -> str:
    """Print each measured row and the all-nonzero bound derived from it."""
    lines = [
        "ERC-5564 announcement gas, canonical runtime, Prague",
        "",
        f"{'case':<22}{'kind':<22}{'payload':>9}{'gasUsed':>10}{'rule':>10}"
        f"{'all-nonzero':>13}",
        "-" * 86,
    ]
    for result in artifact["results"]:
        primary = result["transaction"]
        lines.append(
            f"{result['name']:<22}{result['kind']:<22}"
            f"{result['epk_bytes'] + result['metadata_bytes']:>9}"
            f"{primary['gas_used']:>10}"
            f"{('floor' if floor_binds(primary) else 'standard'):>10}"
            f"{result['upper_bound_gas']:>13}"
        )
    lines += ["-" * 86,
              "all-nonzero is DERIVED from the row beside it, not a second measurement."]
    return "\n".join(lines)


BENCHMARK = Benchmark("announcement", OUT, collect, render)


if __name__ == "__main__":
    raise SystemExit(main_one(BENCHMARK))
