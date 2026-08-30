"""Real deterministic Scheme 3 fixture produced by the Rust implementation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from harness.evm import run
from tools import derive_sizes


ROOT = Path(__file__).resolve().parent.parent
COMMAND = [
    "cargo",
    "run",
    "-q",
    "--example",
    "emit_payment_json",
    "-p",
    "pqsa-per-payment",
    "--locked",
]


def _hex(value: object, field: str, size: int) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"fixture field {field} is not 0x-prefixed hex")
    try:
        decoded = bytes.fromhex(value[2:])
    except ValueError as exc:
        raise RuntimeError(f"fixture field {field} is not valid hex") from exc
    if len(decoded) != size:
        raise RuntimeError(
            f"fixture field {field} is {len(decoded)} bytes, expected {size}"
        )
    return decoded


@dataclass(frozen=True)
class Fixture:
    """One identified Scheme 3 fixture produced by the Rust implementation."""

    name: str
    sha256: str
    scheme_id: int
    meta_address: bytes
    stealth_address: bytes
    spend_key: bytes
    epk: bytes
    metadata: bytes


def generate() -> Fixture:
    """Run and strictly decode the deterministic Rust fixture generator."""
    try:
        body = json.loads(run(COMMAND, cwd=ROOT))
    except json.JSONDecodeError as exc:
        raise RuntimeError("fixture generator did not emit valid JSON") from exc
    fields = {
        "name",
        "scheme_id",
        "meta_address",
        "stealth_address",
        "spend_key",
        "epk_field",
        "metadata",
    }
    if not isinstance(body, dict) or set(body) != fields:
        raise RuntimeError("fixture output does not match the fixture schema")
    if body["name"] != "scheme3-demo-v1" or body["scheme_id"] != 3:
        raise RuntimeError("fixture output has an unknown identity")

    shape = derive_sizes.SHAPES["schemeId 3 announcement"]
    meta_address_bytes = derive_sizes.META["schemeId 3"][0]

    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    return Fixture(
        name=body["name"],
        sha256=hashlib.sha256(canonical).hexdigest(),
        scheme_id=body["scheme_id"],
        meta_address=_hex(body["meta_address"], "meta_address", meta_address_bytes),
        stealth_address=_hex(body["stealth_address"], "stealth_address", 20),
        spend_key=_hex(body["spend_key"], "spend_key", 32),
        epk=_hex(body["epk_field"], "epk_field", shape[0]),
        metadata=_hex(body["metadata"], "metadata", shape[1]),
    )
