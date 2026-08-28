#!/usr/bin/env python3
"""What a whole stealth payment costs: announce, fund, spend.

    python3 measure.py                # boots its own anvil, prints the table
    python3 measure.py --json         # rewrites measured.json
    python3 measure.py --rpc-url URL  # against an already-running node

Needs `anvil`, `cast` and `forge` on PATH, and `cargo`. Exits 1 if any self-check fails.

WHY THIS EXISTS SEPARATELY FROM `harness/announcement`
------------------------------------------------------

That harness measures ONE transaction: the ERC-5564 `announce()` call. It is the
transaction whose size the whole ladder is an argument about -- but it is not what a
payment costs, and a reader of §7's figures might reasonably assume otherwise. A payment is three transactions:

  1. `announce(schemeId, stealthAddress, ephemeralPubKey, metadata)`   -- measured there
  2. a value transfer to `stealthAddress`                              -- measured only here
  3. a spend FROM `stealthAddress`, signed with the derived key        -- measured only here

(2) and (3) are the same for every scheme, because the derived address is an ordinary EOA and the
key is an ordinary secp256k1 scalar -- which is exactly the claim schemeIds 2 and 3 make, and a
claim of that shape is only establishable against a chain. Measuring them is therefore worth more
as a DEMONSTRATION than as a cost: (3) succeeding is proof that the key a recipient derives
controls the address a sender paid, established against an EVM rather than against our own
assertion.

WHAT IT DOES NOT ESTABLISH
--------------------------

A local node is not mainnet, and this measures gas rather than price. (2) and (3) are also
uninteresting as gas -- a transfer to a cold account and an ordinary send -- so the numbers below
matter mostly as a denominator: they are what the announcement's cost should be compared against
when someone asks whether a post-quantum stealth payment is expensive.

INPUT
-----

Derivations are NOT done here. This harness does not implement the scheme and must not: the
reference implementation does, and a second implementation in the measuring tool is a second
thing that can be wrong. It reads `payment.json`, and this schema is the whole contract between
the two — validated here before anything is spent:

    {"cases": [{"scheme_id": 2, "stealth_address": "0x..", "spend_key": "0x..",
                "epk_field": "0x..", "metadata": "0x.."}]}

**Where that file comes from depends on the tree.** One carrying the end-to-end demonstration
crate emits it with one command against that crate, and the emitter there refuses any seed but
the hard-coded demonstration one. A tree carrying only the per-payment library has no such
emitter and no such refusal: the reader derives these fields themselves, and the guarantee below
is then theirs to uphold rather than a check that has already run.

`spend_key` is a secret and this is the one context where printing one is acceptable: every value
in that file is meant to derive from a hard-coded demonstration seed, on a throwaway local chain,
where the addresses hold nothing but anvil's play money. **It MUST NOT be generated from a real
seed.** That sentence is the requirement in every tree; only some trees have a tool enforcing it.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CONTRACTS = ROOT / "contracts"
INPUT = HERE / "payment.json"
OUT = HERE / "measured.json"

# anvil's first dev account. The funder, and nothing else.
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Its address, and the destination of every spend.
#
# An EOA, deliberately. A spend sent to the ANNOUNCER contract instead -- which has no
# `receive` -- is mined (signed by the derived key, `from` the derived address, 21 000 gas
# charged) and then REVERTS. `cast` reports failure and a harness reads it as "the key does
# not work", which is wrong in the most misleading possible direction: the signature is
# valid and the account pays, and the only thing wrong is the recipient.
#
# Worth the paragraph because a reverted spend and an unspendable address look identical from a
# non-zero exit code, and this harness exists to tell them apart.
DEV_ADDR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
INTRINSIC = 21_000


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Node:
    """A pinned anvil, or an already-running node.

    Pinned to Prague for the same reason the announcement harness is: EIP-7623 arrived with it,
    and leaving the fork to anvil's default would silently reprice everything on a toolchain bump.
    """

    def __init__(self, rpc_url=None):
        self.proc = None
        if rpc_url:
            self.url = rpc_url
            return
        port = free_port()
        self.url = f"http://127.0.0.1:{port}"
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


def deploy(url):
    bytecode = run(
        ["forge", "inspect", "ERC5564Announcer", "bytecode", "--root", str(CONTRACTS)]
    ).strip()
    out = run(["cast", "send", "--rpc-url", url, "--private-key", DEV_KEY,
               "--create", bytecode, "--json"])
    return json.loads(out)["contractAddress"]


def gas_of(receipt_json: str) -> int:
    return int(json.loads(receipt_json)["gasUsed"], 16)


def announce(url, announcer, scheme_id, address, epk, metadata):
    calldata = run(["cast", "calldata",
                    "announce(uint256,address,bytes,bytes)",
                    str(scheme_id), address, epk, metadata]).strip()
    return gas_of(run(["cast", "send", "--rpc-url", url, "--private-key", DEV_KEY,
                       "--json", announcer, calldata]))


def fund(url, address, wei):
    return gas_of(run(["cast", "send", "--rpc-url", url, "--private-key", DEV_KEY,
                       "--json", "--value", str(wei), address]))


def spend(url, spend_key, to, wei):
    """A send FROM the derived address, signed with the derived key.

    This is the assertion, not the measurement. If the key does not control the address, `cast`
    fails here -- and it fails against an EVM's own signature recovery rather than against a
    reimplementation of it in this file.

    **The receipt's status is checked, not just the exit code.** A transaction can be mined,
    signed correctly, charged for, and still revert; that is what happened when the destination
    was a contract with no `receive`, and it is indistinguishable from an unspendable address if
    only the exit code is read.
    """
    out = run(["cast", "send", "--rpc-url", url, "--private-key", spend_key,
               "--json", "--value", str(wei), to])
    receipt = json.loads(out)
    if int(receipt["status"], 16) != 1:
        raise RuntimeError(
            f"the spend was mined and REVERTED (status {receipt['status']}), from "
            f"{receipt.get('from')} to {receipt.get('to')}. The signature was accepted -- the "
            f"key controls the address -- so this is the DESTINATION refusing the value, not a "
            f"derivation defect."
        )
    return gas_of(out)


def cases():
    if not INPUT.is_file():
        print(f"usage error: no {INPUT.name}. Produce it from the reference implementation: "
              f"where the workspace carries the end-to-end demonstration crate, that crate's "
              f"--emit-payment-json writes it; where it carries only the per-payment crate, "
              f"derive the same fields from `input_seed` per this directory's README, which "
              f"is the schema this tool validates against before it spends anything.",
              file=sys.stderr)
        raise SystemExit(2)
    body = json.loads(INPUT.read_text())
    got = body.get("cases")
    if not got:
        print(f"usage error: {INPUT.name} has no `cases`", file=sys.stderr)
        raise SystemExit(2)

    # THE SCHEMA, checked here because this directory's README promises it is. A non-empty
    # `cases` array is not validation: the announcer accepts arbitrary bytes, so a malformed
    # wire shape reaches it and produces a measurement stamped `"self_check": "pass"`. A harness
    # that measures the wrong shape and reports success is worse than one that refuses to run.
    #
    # Widths come from §6's wire table for the scheme named in the case, so a payload of the wrong
    # length for its own `schemeId` fails here rather than being priced.
    #
    # **The two schemes put different things in the same two fields, and that is the whole reason
    # the table is keyed by `schemeId`.** schemeId 2 carries the KEM ciphertext in
    # `ephemeralPubKey` and the bare view tag in `metadata`; schemeId 3 carries the EC ephemeral
    # point in `ephemeralPubKey` and `view_tag ‖ ct` in `metadata`. Both payloads total within
    # 33 bytes of each other, so a table with the two schemes transposed still looks plausible: a
    # transposed schemeId 2 would REJECT the reference implementation's own conforming output
    # while accepting a shape its scanner refuses, and nothing about the sizes would look wrong.
    # The pairs below are read off §6's wire table row by row, and this harness needs a node --
    # so `cargo test` is silent about them and only a real run against a node is evidence.
    WIRE = {3: (33, 1089)}
    for i, c in enumerate(got):
        where = f"{INPUT.name} case {i}"
        missing = [k for k in ("scheme_id", "stealth_address", "spend_key", "epk_field",
                               "metadata") if k not in c]
        if missing:
            print(f"usage error: {where} is missing {', '.join(missing)}", file=sys.stderr)
            raise SystemExit(2)
        sid = c["scheme_id"]
        if sid not in WIRE:
            print(f"usage error: {where} names schemeId {sid}, and this harness prices the "
                  f"per-payment schemes {sorted(WIRE)}", file=sys.stderr)
            raise SystemExit(2)
        for field, want in (("stealth_address", 20), ("spend_key", 32),
                            ("epk_field", WIRE[sid][0]), ("metadata", WIRE[sid][1])):
            v = c[field]
            if not isinstance(v, str) or not v.startswith("0x"):
                print(f"usage error: {where} field `{field}` is not a 0x-prefixed hex string",
                      file=sys.stderr)
                raise SystemExit(2)
            try:
                raw = bytes.fromhex(v[2:])
            except ValueError:
                print(f"usage error: {where} field `{field}` is not valid hex", file=sys.stderr)
                raise SystemExit(2)
            if len(raw) != want:
                print(f"usage error: {where} field `{field}` is {len(raw)} bytes and schemeId "
                      f"{sid} requires {want} per §6's wire table -- the announcer would accept "
                      f"it and the measurement would price a shape this document does not "
                      f"specify", file=sys.stderr)
                raise SystemExit(2)
    return body, got


def main(argv):
    args = argv[1:]
    write = "--json" in args
    if write:
        args.remove("--json")
    rpc = None
    if "--rpc-url" in args:
        k = args.index("--rpc-url")
        if k + 1 >= len(args):
            print("usage error: --rpc-url needs a URL", file=sys.stderr)
            return 2
        rpc = args[k + 1]
        del args[k:k + 2]
    if args:
        print(__doc__, file=sys.stderr)
        return 2

    body, got = cases()
    node = Node(rpc)
    results = []
    try:
        announcer = deploy(node.url)
        for c in got:
            addr, key = c["stealth_address"], c["spend_key"]
            # 1 ETH in, then send 0.5 back out: enough that the spend cannot be mistaken for a
            # zero-value transaction, and enough left over to pay for itself.
            a = announce(node.url, announcer, c["scheme_id"], addr,
                         c["epk_field"], c["metadata"])
            f = fund(node.url, addr, 10**18)
            s = spend(node.url, key, DEV_ADDR, 5 * 10**17)
            results.append({
                "scheme_id": c["scheme_id"],
                "announce_gas": a,
                "fund_gas": f,
                "spend_gas": s,
                "total_gas": a + f + s,
            })
    finally:
        node.close()

    bad = check(results)
    print(table(results))
    if bad:
        print("\nFAIL:")
        for b in bad:
            print(f"  {b}")
        return 1
    if write:
        OUT.write_text(json.dumps({
            "harness": "payment",
            "what": "gas for a whole stealth payment: announce, fund the derived address, "
                    "then spend from it with the derived key",
            "hardfork": "prague",
            "intrinsic_gas": INTRINSIC,
            "input_seed": body.get("seed_label", "unstated"),
            "self_check": "pass",
            "cases": results,
        }, indent=1) + "\n")
        print(f"\nwrote {OUT}")
    return 0


def check(results):
    """Self-checks, and the third is the only one that is really about cryptography."""
    bad = []
    for r in results:
        if r["fund_gas"] < INTRINSIC:
            bad.append(f"schemeId {r['scheme_id']}: a transfer below the intrinsic floor "
                       f"({r['fund_gas']}), which cannot happen -- the measurement is wrong")
        # A transfer to an account with no code and no prior balance is the intrinsic cost plus
        # EIP-2929's cold-account access and the new-account charge. Anything far above it means
        # the derived address is NOT an empty EOA, which would contradict the whole scheme.
        if r["fund_gas"] > 40_000:
            bad.append(f"schemeId {r['scheme_id']}: funding cost {r['fund_gas']}, too high for "
                       f"an empty EOA -- the derived address may have code")
        if r["spend_gas"] < INTRINSIC:
            bad.append(f"schemeId {r['scheme_id']}: spend below the intrinsic floor")
        if r["announce_gas"] <= r["fund_gas"]:
            bad.append(f"schemeId {r['scheme_id']}: the announcement ({r['announce_gas']}) cost "
                       f"no more than a bare transfer ({r['fund_gas']}), which would mean the "
                       f"payload never reached the chain")
    if not results:
        bad.append("no cases measured, and an empty table reads like a passing one")
    return bad


def table(results):
    lines = [
        "whole-payment gas, Prague, local node",
        "",
        f"{'scheme':<10}{'announce':>10}{'fund':>9}{'spend':>9}{'total':>10}"
        f"{'announce %':>12}",
    ]
    for r in results:
        pct = 100 * r["announce_gas"] / r["total_gas"]
        lines.append(f"schemeId {r['scheme_id']:<2}{r['announce_gas']:>10}{r['fund_gas']:>9}"
                     f"{r['spend_gas']:>9}{r['total_gas']:>10}{pct:>11.1f}%")
    lines += [
        "",
        "`fund` and `spend` are identical work for every scheme -- the derived address is an",
        "ordinary EOA and the derived key an ordinary scalar -- so the schemes differ only in the",
        "first column. The spend SUCCEEDING is the point: it is the EVM agreeing that the key",
        "the recipient derived controls the address the sender paid.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
