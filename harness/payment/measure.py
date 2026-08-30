#!/usr/bin/env python3
"""Live end-to-end native-ETH stealth payment gas benchmark."""

from __future__ import annotations

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
from harness.evm import (  # noqa: E402
    Anvil,
    DEV_ADDRESS,
    DEV_KEY,
    HARDFORK,
    gas_used,
    quantity,
    require_route,
    rpc,
    run,
    send,
)
from harness.runner import Benchmark, Context, main_one  # noqa: E402
from tools import derive_sizes  # noqa: E402


OUT = Path(__file__).resolve().parent / "measured.json"
FUND_VALUE = 10**18
SPEND_VALUE = 5 * 10**17


def _address(private_key: bytes) -> str:
    return run(
        [
            "cast",
            "wallet",
            "address",
            "--private-key",
            "0x" + private_key.hex(),
        ]
    ).strip()


def _balance(url: str, address: str) -> int:
    return quantity(rpc(url, "eth_getBalance", [address, "latest"]))


def _require_eoa(url: str, address: str, label: str) -> None:
    if rpc(url, "eth_getCode", [address, "latest"]) != "0x":
        raise RuntimeError(f"{label} {address} is not an EOA")


def _announcement_calldata_bytes() -> int:
    epk_bytes, metadata_bytes = derive_sizes.SHAPES["schemeId 3 announcement"]
    return (
        4
        + 4 * 32
        + 32
        + 32 * ((epk_bytes + 31) // 32)
        + 32
        + 32 * ((metadata_bytes + 31) // 32)
    )


def collect(context: Context) -> dict:
    """Generate and execute one real Scheme 3 announcement, fund, and spend."""
    fixture = context.fixture
    stealth_address = "0x" + fixture.stealth_address.hex()
    spend_key = "0x" + fixture.spend_key.hex()
    if _address(fixture.spend_key).lower() != stealth_address.lower():
        raise RuntimeError("fixture spend key does not control the stealth address")

    with Anvil() as node:
        install_announcer(node.url)
        _require_eoa(node.url, DEV_ADDRESS, "spend destination")
        _require_eoa(node.url, stealth_address, "stealth address")
        if _balance(node.url, stealth_address) != 0:
            raise RuntimeError("stealth address did not start empty")

        announce_receipt, calldata = send_announcement(
            node.url,
            fixture.scheme_id,
            stealth_address,
            "0x" + fixture.epk.hex(),
            "0x" + fixture.metadata.hex(),
        )
        calldata_bytes = bytes.fromhex(calldata.removeprefix("0x"))
        if len(calldata_bytes) != _announcement_calldata_bytes():
            raise RuntimeError("announcement transaction has the wrong calldata shape")
        fund_receipt = send(
            node.url, DEV_KEY, "--value", str(FUND_VALUE), stealth_address
        )
        require_route(fund_receipt, DEV_ADDRESS, stealth_address, "fund")
        if _balance(node.url, stealth_address) != FUND_VALUE:
            raise RuntimeError("fund transaction transferred the wrong value")

        destination_before = _balance(node.url, DEV_ADDRESS)
        spend_receipt = send(
            node.url,
            spend_key,
            "--value",
            str(SPEND_VALUE),
            DEV_ADDRESS,
        )
        require_route(spend_receipt, stealth_address, DEV_ADDRESS, "spend")
        spend_gas = gas_used(spend_receipt)
        effective_price = quantity(spend_receipt.get("effectiveGasPrice"))
        if _balance(node.url, DEV_ADDRESS) - destination_before != SPEND_VALUE:
            raise RuntimeError("spend transaction transferred the wrong value")
        expected_remainder = FUND_VALUE - SPEND_VALUE - spend_gas * effective_price
        if _balance(node.url, stealth_address) != expected_remainder:
            raise RuntimeError("stealth balance does not account for value and fee")

    return {
        "schema_version": 1,
        "benchmark": "payment",
        "environment": {
            "hardfork": HARDFORK,
            "announcer_address": ANNOUNCER,
            "announcer_code_sha256": ANNOUNCER_SHA256,
        },
        "fixture": {
            "name": fixture.name,
            "sha256": fixture.sha256,
        },
        "results": [
            {
                "name": "scheme3_real_sample",
                "scheme_id": fixture.scheme_id,
                "kind": "real_sample",
                "transactions": {
                    "announce": {
                        "calldata_bytes": len(calldata_bytes),
                        "zero_bytes": calldata_bytes.count(0),
                        "gas_used": gas_used(announce_receipt),
                    },
                    "fund": {"gas_used": gas_used(fund_receipt)},
                    "spend": {"gas_used": spend_gas},
                },
            }
        ],
    }


def render(artifact: dict) -> str:
    transactions = artifact["results"][0]["transactions"]
    total = sum(observation["gas_used"] for observation in transactions.values())
    return "\n".join(
        [
            "Scheme 3 native-ETH payment gas, Rust fixture, Prague",
            "",
            f"{'announce':>10}{'fund':>10}{'spend':>10}{'total':>11}",
            f"{transactions['announce']['gas_used']:>10}"
            f"{transactions['fund']['gas_used']:>10}"
            f"{transactions['spend']['gas_used']:>10}{total:>11}",
        ]
    )


BENCHMARK = Benchmark("payment", OUT, collect, render)


if __name__ == "__main__":
    raise SystemExit(main_one(BENCHMARK))
