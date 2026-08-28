#!/usr/bin/env python3
"""Registration cost, measured as real first-time `registerKeys` transactions against the
canonical ERC-6538 registry's DEPLOYED runtime bytecode.

    python3 measure.py                # boots its own anvil, prints the table
    python3 measure.py --json         # rewrites measured.json
    python3 measure.py --rpc-url URL  # an already-running node, which must allow anvil_setCode

Requires `anvil` and `cast` (Foundry) on PATH.

WHAT EACH CONVENTION IS AND WHY IT MOVES THE NUMBER IS STATED HERE, at the point the
convention is applied, and is deliberately NOT repeated in `README.md`. It used to be in
both places: the two copies drifted, and every stale claim this directory has carried was
carried twice. One home, and this is it -- the reader who needs a convention is reading
the code that applies it.
"""

import argparse
import hashlib
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent

sys.path.insert(0, str(ROOT / "tools"))
import derive_sizes  # noqa: E402

# The canonical ERC-6538 registry singleton. Same address on every chain it is deployed to.
REGISTRY = "0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538"

# SHA-256 of the runtime bytecode in `deployed_bytecode.hex` (the 0x-prefixed hex line's
# decoded bytes), as read from mainnet with `eth_getCode` at block 25 832 859. Pinned so a
# swapped or truncated file fails before anything is measured.
BYTECODE_SHA256 = "aacd1016938b107361de63f20c358350de9f78fa6033b7727853f0229c94b82f"

SIG = "registerKeys(uint256,bytes)"

# One fresh key per row: FIRST registration requires a registrant whose entry is empty, and
# rows may share a schemeId. Any 32-byte scalar is a secp256k1 key;
# these are funded via `anvil_setBalance`, so nothing here depends on anvil's account list.
KEYS = [f"0x{i:064x}" for i in range(1, 1 + len(derive_sizes.REGISTRATION_RATIOS))]


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def blob(n):
    """Payload bytes, none of them zero -- a worst-case calldata convention, stated.

    Byte VALUES cannot reach the storage cost that dominates these rows: a slot is charged
    zero-to-nonzero unless all 32 of its bytes are zero, which real key material gives with
    probability about 2**-256. They do reach the CALLDATA cost, which these rows pay on
    EIP-7623's standard path, where a zero byte is 12 gas cheaper than a nonzero one -- and
    real key material carries about one zero byte in 256.

    So every figure this harness reports is an UPPER BOUND on what a real registration pays,
    over by roughly `size / 256 * 12` gas: about 59 gas at schemeId 3's 1 250 bytes, about 3
    at the classical 66. `tools/derive_sizes.py` derives that per row from the EIP-7623
    constants rather than from any number typed here, and fails if the two disagree.
    """
    return "0x" + "".join(f"{1 + (i % 255):02x}" for i in range(n))


def rpc(url, method, params):
    out = run(["cast", "rpc", "--rpc-url", url, method, json.dumps(params), "--raw"])
    return out.strip()


class Node:
    def __init__(self, rpc_url=None):
        self.proc = None
        if rpc_url:
            self.url = rpc_url
            return
        port = free_port()
        self.url = f"http://127.0.0.1:{port}"
        # Pin the fork, same reason as the announcement harness: leaving it to anvil's
        # default would silently reprice everything on a toolchain bump.
        self.proc = subprocess.Popen(
            ["anvil", "--hardfork", "prague", "--port", str(port), "--silent"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        for _ in range(100):
            try:
                run(["cast", "block-number", "--rpc-url", self.url])
                return
            except subprocess.CalledProcessError:
                time.sleep(0.1)
        raise RuntimeError("anvil did not come up")

    def close(self):
        if self.proc:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            self.proc.wait()


def install_registry(url):
    """`anvil_setCode` the canonical runtime bytecode at its canonical address.

    The registry's constructor only bakes the EIP-712 domain values into immutables, which
    the runtime bytecode already carries; `registerKeys` never reads them, so the installed
    code behaves exactly as the mainnet deployment for what is measured here.
    """
    code = (HERE / "deployed_bytecode.hex").read_text().strip()
    digest = hashlib.sha256(bytes.fromhex(code[2:])).hexdigest()
    if digest != BYTECODE_SHA256:
        raise SystemExit(
            f"deployed_bytecode.hex does not hash to the pinned value\n"
            f"  pinned:   {BYTECODE_SHA256}\n  computed: {digest}\n"
            f"re-derive the file with: cast rpc eth_getCode {REGISTRY} latest --rpc-url <mainnet>"
        )
    rpc(url, "anvil_setCode", [REGISTRY, code])


def rows():
    """`(name, schemeId, meta_len, key)` per row of §6's registration table.

    Lengths come from `derive_sizes.REGISTRATION_RATIOS`, which re-derives them from
    FIPS 203 and asserts them against §6/§4.2.
    """
    out = []
    for (label, (meta_len, _ratio)), key in zip(
        derive_sizes.REGISTRATION_RATIOS.items(), KEYS
    ):
        scheme_id = int(label.split(",")[0])
        name = (f"schemeId {label} registration" if "," in label
                else f"schemeId {label} registration"
                if label != "1" else "classical (ERC-5564 schemeId 1) registration")
        out.append((name, scheme_id, meta_len, key))
    return out


def measure(url):
    results = []
    for name, scheme_id, meta_len, key in rows():
        addr = run(["cast", "wallet", "address", "--private-key", key]).strip()
        rpc(url, "anvil_setBalance", [addr, "0x21e19e0c9bab2400000"])
        calldata = run(
            ["cast", "calldata", SIG, str(scheme_id), blob(meta_len)]
        ).strip()
        out = run(
            ["cast", "send", "--rpc-url", url, "--private-key", key,
             "--json", REGISTRY, calldata]
        )
        receipt = json.loads(out)
        gas = int(receipt["gasUsed"], 16)
        if int(receipt["status"], 16) != 1:
            raise SystemExit(f"{name}: the registration transaction reverted")
        results.append({
            "name": name,
            "schemeId": scheme_id,
            "meta_address_bytes": meta_len,
            "calldata_bytes": len(calldata) // 2 - 1,
            "total_gas": gas,
        })
    return results


def check(results):
    """The claims a wrong harness would silently break, asserted after every run."""
    problems = []
    want = {r[1]: r[2] for r in [(n, s, m) for n, s, m, _ in rows()]}
    lens = [(r["schemeId"], r["meta_address_bytes"]) for r in results]
    for (label, (meta_len, _)), r in zip(derive_sizes.REGISTRATION_RATIOS.items(), results):
        if r["meta_address_bytes"] != meta_len:
            problems.append(f"{r['name']}: measured a {r['meta_address_bytes']} B payload "
                            f"where the table derives {meta_len} B")
    # Storage dominance, the table's own claim: gas must grow with the meta-address at
    # far above calldata rates. 22 100 gas per fresh 32-byte slot is the floor of what
    # a first registration stores; a figure below meta_len/32 * 20k means the registry
    # did not store the payload and the measurement is of something else.
    for r in results:
        slots = (r["meta_address_bytes"] + 31) // 32
        if r["total_gas"] < slots * 20_000:
            problems.append(f"{r['name']}: {r['total_gas']} gas cannot have stored "
                            f"{slots} fresh slots")
    _ = (want, lens)
    return problems


def table(results):
    print(f"{'row':44} {'meta B':>7} {'calldata B':>10} {'total gas':>10}")
    for r in results:
        print(f"{r['name']:44} {r['meta_address_bytes']:>7} "
              f"{r['calldata_bytes']:>10} {r['total_gas']:>10}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--rpc-url")
    args = ap.parse_args()

    node = Node(args.rpc_url)
    try:
        install_registry(node.url)
        results = measure(node.url)
    finally:
        node.close()

    problems = check(results)
    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1

    if args.json:
        body = {
            "harness": "registration",
            "what": "first-time ERC-6538 registerKeys cost per schemeId, measured as real "
                    "transactions against the CANONICAL registry's deployed runtime bytecode "
                    "(mainnet 0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538, installed with "
                    "anvil_setCode), one fresh registrant per row",
            "hardfork": "prague",
            "registry_bytecode_sha256": BYTECODE_SHA256,
            "registry_bytecode_source": "eth_getCode 0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538 "
                                        "latest (mainnet, block 25832859)",
            "self_check": "pass",
            "cases": results,
        }
        (HERE / "measured.json").write_text(json.dumps(body, indent=2) + "\n",
                                            encoding="utf-8")
        print(f"wrote {HERE / 'measured.json'}")
    else:
        table(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
