"""Small, shared EVM plumbing for the gas benchmarks."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import time
from pathlib import Path


DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEV_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
HARDFORK = "prague"


def run(cmd: list[str], **kwargs) -> str:
    """Run a command and return stdout, raising with stderr on failure."""
    try:
        return subprocess.run(
            cmd, check=True, capture_output=True, text=True, **kwargs
        ).stdout
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise RuntimeError(f"{' '.join(cmd[:2])} failed: {detail}") from exc


def rpc(url: str, method: str, params: list[object]):
    """Call one JSON-RPC method through cast and decode its JSON result."""
    raw = run(
        ["cast", "rpc", "--rpc-url", url, method, json.dumps(params), "--raw"]
    ).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw


def quantity(value: int | str) -> int:
    """Decode a JSON-RPC quantity or accept an integer unchanged."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise ValueError(f"not a JSON-RPC quantity: {value!r}")


def send(url: str, private_key: str, *args: str) -> dict:
    """Send a transaction and return a successful receipt."""
    receipt = json.loads(
        run(
            [
                "cast",
                "send",
                "--rpc-url",
                url,
                "--private-key",
                private_key,
                "--json",
                *args,
            ]
        )
    )
    try:
        status = quantity(receipt["status"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "cast send returned a receipt without a valid status"
        ) from exc
    if status != 1:
        raise RuntimeError(
            f"transaction reverted: from={receipt.get('from')} "
            f"to={receipt.get('to')} status={receipt.get('status')}"
        )
    return receipt


def gas_used(receipt: dict) -> int:
    """Read gasUsed from a transaction receipt."""
    try:
        return quantity(receipt["gasUsed"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("receipt has no valid gasUsed") from exc


def require_route(receipt: dict, sender: str, recipient: str, label: str) -> None:
    """Require a receipt to describe the intended sender and recipient."""
    actual_sender = str(receipt.get("from", ""))
    actual_recipient = str(receipt.get("to", ""))
    if (
        actual_sender.lower() != sender.lower()
        or actual_recipient.lower() != recipient.lower()
    ):
        raise RuntimeError(
            f"{label} receipt route is {actual_sender} -> {actual_recipient}, "
            f"expected {sender} -> {recipient}"
        )


def load_runtime(path: Path, expected_sha256: str) -> str:
    """Load a 0x-prefixed runtime bytecode fixture and verify its digest."""
    code = path.read_text(encoding="utf-8").strip()
    if not code.startswith("0x"):
        raise RuntimeError(f"{path} is not 0x-prefixed runtime bytecode")
    try:
        digest = hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()
    except ValueError as exc:
        raise RuntimeError(f"{path} is not valid hex") from exc
    if digest != expected_sha256:
        raise RuntimeError(
            f"{path} bytecode hash mismatch: expected {expected_sha256}, got {digest}"
        )
    return code


def set_code_checked(
    url: str, address: str, code: str, expected_sha256: str
) -> None:
    """Install runtime bytecode and verify the node stored exactly those bytes."""
    result = rpc(url, "anvil_setCode", [address, code])
    if result not in (None, True):
        raise RuntimeError(f"anvil_setCode returned {result!r}")
    installed = rpc(url, "eth_getCode", [address, "latest"])
    if not isinstance(installed, str) or installed.lower() != code.lower():
        raise RuntimeError(
            f"eth_getCode did not return the installed code at {address}"
        )
    digest = hashlib.sha256(bytes.fromhex(installed[2:])).hexdigest()
    if digest != expected_sha256:
        raise RuntimeError(
            "installed bytecode hash mismatch: "
            f"expected {expected_sha256}, got {digest}"
        )


class Anvil:
    """Fresh local Anvil node running the benchmark hardfork."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.url = ""

    def __enter__(self) -> "Anvil":
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        self.url = f"http://127.0.0.1:{port}"
        self.proc = subprocess.Popen(
            ["anvil", "--hardfork", HARDFORK, "--port", str(port), "--silent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            if self.proc.poll() is not None:
                self.close()
                raise RuntimeError("anvil exited during startup")
            try:
                run(["cast", "block-number", "--rpc-url", self.url])
                return self
            except RuntimeError:
                time.sleep(0.1)
        self.close()
        raise RuntimeError("anvil did not come up")

    def close(self) -> None:
        """Stop the node if it is running."""
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            self.proc = None

    def __exit__(self, _kind, _value, _traceback) -> None:
        self.close()
