#!/usr/bin/env python3
"""Live first-registration gas benchmark for the canonical ERC-6538 registry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.evm import (  # noqa: E402
    Anvil,
    HARDFORK,
    gas_used,
    load_runtime,
    quantity,
    require_route,
    rpc,
    run,
    send,
    set_code_checked,
)
from harness.eip7623 import INTRINSIC, all_nonzero_payload_bound  # noqa: E402
from harness.runner import Benchmark, Context, main_one  # noqa: E402
from tools import derive_sizes  # noqa: E402


HERE = Path(__file__).resolve().parent
OUT = HERE / "measured.json"
REGISTRY = "0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538"
REGISTRY_SHA256 = "aacd1016938b107361de63f20c358350de9f78fa6033b7727853f0229c94b82f"
BYTECODE = HERE / "deployed_bytecode.hex"
REGISTER_SIG = "registerKeys(uint256,bytes)"
GET_SIG = "stealthMetaAddressOf(address,uint256)(bytes)"


@dataclass(frozen=True)
class Case:
    name: str
    scheme_id: int
    kind: str
    meta_address: bytes
    private_key: str


def _nonzero(length: int) -> bytes:
    return bytes(1 + index % 255 for index in range(length))


def _cases(context: Context) -> list[Case]:
    """One measured row per schemeId, each with its own fresh registrant.

    schemeId 3 registers the real fixture meta-address. schemeId 1 has no fixture, so its
    row is CONSTRUCTED at the right width with no zero byte -- a reference point, not a
    sample. The all-nonzero cost of both is derived in `harness/eip7623.py` rather than
    registered a second time.
    """
    fixture = context.fixture
    if len(fixture.meta_address) != derive_sizes.META["schemeId 3"][0]:
        raise RuntimeError("fixture meta-address does not match Section 6's width")
    return [
        Case(
            "classical_reference",
            1,
            "constructed_reference",
            _nonzero(derive_sizes.META_CLASSICAL),
            "0x" + f"{1:064x}",
        ),
        Case(
            "scheme3_real_sample",
            3,
            "real_sample",
            fixture.meta_address,
            "0x" + f"{3:064x}",
        ),
    ]


def _stored(url: str, registrant: str, scheme_id: int) -> str:
    value = run(
        [
            "cast",
            "call",
            "--rpc-url",
            url,
            REGISTRY,
            GET_SIG,
            registrant,
            str(scheme_id),
        ]
    ).strip()
    return value.strip('"')


def _fund(url: str, address: str) -> None:
    amount = 10**23
    result = rpc(url, "anvil_setBalance", [address, hex(amount)])
    if result not in (None, True):
        raise RuntimeError(f"anvil_setBalance returned {result!r}")
    if quantity(rpc(url, "eth_getBalance", [address, "latest"])) != amount:
        raise RuntimeError(f"failed to fund registration caller {address}")


def _execute(url: str, case: Case) -> dict[str, int]:
    registrant = run(
        ["cast", "wallet", "address", "--private-key", case.private_key]
    ).strip()
    _fund(url, registrant)
    if _stored(url, registrant, case.scheme_id) != "0x":
        raise RuntimeError(f"{case.name}: registry entry was not empty")

    payload = "0x" + case.meta_address.hex()
    calldata = run(
        ["cast", "calldata", REGISTER_SIG, str(case.scheme_id), payload]
    ).strip()
    receipt = send(url, case.private_key, REGISTRY, calldata)
    require_route(receipt, registrant, REGISTRY, case.name)
    if _stored(url, registrant, case.scheme_id).lower() != payload.lower():
        raise RuntimeError(f"{case.name}: registry did not store the submitted bytes")

    raw = bytes.fromhex(calldata.removeprefix("0x"))
    expected_calldata = _calldata_bytes(len(case.meta_address))
    if len(raw) != expected_calldata:
        raise RuntimeError(
            f"{case.name}: calldata is {len(raw)} bytes, expected {expected_calldata}"
        )
    receipt_gas = gas_used(receipt)
    if receipt_gas < INTRINSIC:
        raise RuntimeError(f"{case.name}: invalid receipt gas {receipt_gas}")
    return {
        "calldata_bytes": len(raw),
        "zero_bytes": raw.count(0),
        "gas_used": receipt_gas,
    }


def collect(context: Context) -> dict:
    cases = _cases(context)
    code = load_runtime(BYTECODE, REGISTRY_SHA256)
    with Anvil() as node:
        set_code_checked(node.url, REGISTRY, code, REGISTRY_SHA256)
        results = []
        for case in cases:
            transaction = _execute(node.url, case)
            payload_zero_bytes = case.meta_address.count(0)
            results.append(
                {
                    "name": case.name,
                    "scheme_id": case.scheme_id,
                    "kind": case.kind,
                    "meta_address_bytes": len(case.meta_address),
                    "payload_zero_bytes": payload_zero_bytes,
                    # Derived from the row beside it, never registered. See
                    # `harness/eip7623.py` for why a second transaction is not needed.
                    "upper_bound_gas": all_nonzero_payload_bound(
                        transaction, payload_zero_bytes
                    ),
                    "transaction": transaction,
                }
            )
    return {
        "schema_version": 1,
        "benchmark": "registration",
        "environment": {
            "hardfork": HARDFORK,
            "contract_address": REGISTRY,
            "contract_code_sha256": REGISTRY_SHA256,
        },
        "fixture": {
            "name": context.fixture.name,
            "sha256": context.fixture.sha256,
        },
        "results": results,
    }


def _calldata_bytes(meta_address_bytes: int) -> int:
    return 4 + 2 * 32 + 32 + 32 * ((meta_address_bytes + 31) // 32)


def render(artifact: dict) -> str:
    lines = [
        "ERC-6538 first-registration gas, canonical runtime, Prague",
        "",
        f"{'case':<22}{'kind':<22}{'meta':>8}{'calldata':>10}{'gasUsed':>11}"
        f"{'all-nonzero':>13}",
        "-" * 86,
    ]
    for result in artifact["results"]:
        transaction = result["transaction"]
        lines.append(
            f"{result['name']:<22}{result['kind']:<22}"
            f"{result['meta_address_bytes']:>8}{transaction['calldata_bytes']:>10}"
            f"{transaction['gas_used']:>11}{result['upper_bound_gas']:>13}"
        )
    lines += ["-" * 86,
              "all-nonzero is DERIVED from the row beside it, not a second registration."]
    return "\n".join(lines)


BENCHMARK = Benchmark("registration", OUT, collect, render)


if __name__ == "__main__":
    raise SystemExit(main_one(BENCHMARK))
