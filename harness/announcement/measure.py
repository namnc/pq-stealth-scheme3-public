#!/usr/bin/env python3
"""Announcement cost, measured as real standalone transactions.

WHY THIS EXISTS
---------------
The figures this replaces were measured with `gasleft()` around a call made from
a Foundry test contract. That frame is not the frame a wallet pays in:

  * a test contract reaches the announcer with `CALL`, so it pays EIP-2929 cold
    account access (2 600) plus caller-side argument copy;
  * a standalone transaction executes no `CALL` at all, and EIP-2929 seeds
    `accessed_addresses` with `tx.to`, so there is no cold charge to pay.

Measured here, the test-frame "execution" figure was ~2.1x the real one.  Because
the EIP-7623 floor binds on the post-quantum rungs (where execution is not
charged at all) and does not bind on the classical baseline (where it is), the
whole of that error landed on the denominator of every published ratio.

So this harness sends real transactions to a real deployed announcer on anvil and
reads `gasUsed` off the receipt.  **Total transaction gas needs no convention** --
it is the number a wallet's balance actually moves by.

TWO NUMBERS, AND HOW EACH IS OBTAINED
-------------------------------------
1. `total`      -- straight off the receipt.  Ground truth, no arithmetic.
2. `execution`  -- not directly observable when the floor binds, because the
   transaction then pays `21000 + 10*tokens` regardless of what the EVM did.

   Recovered with a probe: the same call with an **all-zero** payload of the
   same length.  Execution gas is a function of calldata *length*, not of byte
   values (LOG data is 8/byte regardless; memory expansion and CALLDATACOPY are
   length-driven), while the EIP-7623 token count is not -- a zero byte is 1
   token, a nonzero byte is 4.  So the zero variant escapes the floor and
   exposes execution, at identical execution cost.

   That is an assumption, so it is **validated, not asserted**: on the two rungs
   where the floor binds on neither variant, execution is recoverable from both
   and the two must agree exactly. This run fails if they do not -- the check is
   unconditional, not a flag.

Run:
    python3 measure.py                # boots its own anvil, prints the table
    python3 measure.py --json         # rewrites measured.json
    python3 measure.py --rpc-url URL  # against an already-running node

Requires `anvil` and `cast` (Foundry) on PATH, plus `forge` to obtain the
announcer bytecode from ../../contracts.
"""

import argparse
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CONTRACTS = ROOT / "contracts"

# The field lengths are READ from the size harness, not retyped here.
#
# That is the load-bearing design choice in this file. A `CASES` table could be a hand-written list of
# nine field lengths -- and a hand-maintained copy of such a list can carry superseded
# scheme ids and a superseded view-tag width while looking complete, which is the classic
# way a payload table rots without anything failing.
#
# `tools/derive_sizes.py` already owns these lengths, re-derives them from FIPS 203 and FIPS 204
# rather than from any constant that produced them, and asserts them against §6. Reading them
# from there means a wire change cannot leave the gas figures measuring a payload the document
# no longer specifies -- the failure mode a moving wire model makes routine.
sys.path.insert(0, str(ROOT / "tools"))
import derive_sizes  # noqa: E402

# anvil's first default account. Public, published in anvil's own banner.
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# A REAL derived stealth address (schemeId 2's), not a decorative constant.
#
# NOT `0x0000000000000000000000000000000000C0FFEE`: cute, and **three
# nonzero bytes where a real address has twenty**. Under EIP-7623 a zero calldata byte costs one
# token and a nonzero one costs four, and on every post-quantum rung the floor binds -- so the
# decorative address made each of those rows cheaper than the transaction it claimed to price, by
# 51 tokens and therefore **510 gas**.
#
# A second harness measuring the same transaction with a real address disagrees by 480:
# the arithmetic is right, the FIXTURE is not, and a fixture chosen
# for looks is a fixture nobody checks. A ratio computed against it understated the cost of every rung the floor
# binds on, which is all of them except the classical baseline.
#
# This value is `SchemeId2`'s derived address from the demonstration seed -- an output of the
# scheme rather than a number someone typed, so it has a real address's byte distribution by
# construction rather than by anyone's judgement.
#
# For the schemeId 6 rows it is additionally a STAND-IN, and those rows are nonconforming
# wire-shape probes: the section 4.6 address mapping is an open decision, no conforming
# schemeId 6 announcement can exist until it closes, and every substitute address -- this
# one included -- is individually forbidden by section 4.4. The transactions are real and
# their widths are the wire table's, so the rows price the calldata shape a future
# announcement would have; they price no emission section 4 permits, because none is
# expressible. The receipt's `what` field and the documents quoting these rows state the
# same boundary.
STEALTH = "0x6dbb67f21b650304b5f459833188f52db07c2b43"
SIG = "announce(uint256,address,bytes,bytes)"

INTRINSIC = 21_000

# ERC-5564's OWN schemeId 1, which is the baseline every ratio is against.
#
# Hand-stated, because it is not ours: two SEC1-compressed points' worth of announcement --
# a 33-byte ephemeral key and a one-byte view tag -- as `schemeId 1` specifies. It does NOT
# follow this document's eight-byte tag, and writing it as if it did would inflate the
# denominator of every ratio in §7.
CLASSICAL = ("classical (ERC-5564 schemeId 1)", 1, 33, 1)


def cases():
    """`(name, schemeId, epk_len, metadata_len)` for every row §6's wire table has.

    Order: the classical baseline first, then the ladder in `schemeId` order, so the printed
    table reads the way §7's does.
    """
    out = [CLASSICAL]
    for name, (epk_len, md_len) in derive_sizes.SHAPES.items():
        out.append((name, derive_sizes.SHAPE_SCHEME_ID[name], epk_len, md_len))
    return out


CASES = cases()


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def blob(n, fill):
    """Payload bytes.

    `fill='nonzero'` reproduces the pattern the Foundry fixture used
    (`1 + i % 255`, never zero) so the token count is the worst case.
    `fill='zero'` is the execution probe described in the module docstring.
    """
    if fill == "zero":
        return "0x" + "00" * n
    return "0x" + "".join(f"{1 + (i % 255):02x}" for i in range(n))


def tokens_of(calldata_hex):
    """EIP-7623 token count over the whole transaction calldata.

    Not payload-only: this is what the protocol charges, so it is what a wallet
    pays.  A payload-only convention undercounts that, and does so silently
    wherever a document fails to state which convention it uses.
    """
    raw = bytes.fromhex(calldata_hex[2:])
    zero = sum(1 for b in raw if b == 0)
    nonzero = len(raw) - zero
    return zero + 4 * nonzero, zero, nonzero


class Node:
    def __init__(self, rpc_url=None):
        self.proc = None
        if rpc_url:
            self.url = rpc_url
            return
        port = free_port()
        self.url = f"http://127.0.0.1:{port}"
        # Pin the fork. EIP-7623 arrived with Prague; leaving this to anvil's
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


def deploy(url):
    bytecode = run(
        ["forge", "inspect", "ERC5564Announcer", "bytecode", "--root", str(CONTRACTS)]
    ).strip()
    out = run(
        [
            "cast", "send", "--rpc-url", url, "--private-key", DEV_KEY,
            "--create", bytecode, "--json",
        ]
    )
    return json.loads(out)["contractAddress"]


def send(url, to, calldata):
    out = run(
        [
            "cast", "send", "--rpc-url", url, "--private-key", DEV_KEY,
            "--json", to, calldata,
        ]
    )
    return int(json.loads(out)["gasUsed"], 16)


def measure(url, announcer):
    """Send both variants of every case, then derive.

    Two passes on purpose. The zero probe is what yields `execution`, and
    `execution` is what decides whether the floor binds -- so nothing can be
    derived until both receipts are in hand. A tempting shortcut derives
    `floor_binds` inside the send loop as `gas == floor`, which is a DIFFERENT
    predicate from the one `contracts/test/AnnouncementGas.t.sol::_rule` uses
    (`floorCost > standard`): the two disagree at the tie, where `floor == standard`
    and the receipt equals both. Unreachable at these seven payload sizes, but two
    definitions of one predicate -- asserted equal by the Solidity -- is a latent
    contradiction rather than a working cross-check.
    """
    results = []
    for name, scheme_id, epk_len, meta_len in CASES:
        row = {
            "name": name,
            "schemeId": scheme_id,
            "epk_bytes": epk_len,
            "metadata_bytes": meta_len,
            "payload_bytes": epk_len + meta_len,
        }

        # Pass 1: send, and record only what the receipt says. Every row sends
        # STEALTH, the schemeId 6 rows included -- see the stand-in note on that
        # constant: for rung 6 these are nonconforming wire-shape probes.
        for fill in ("nonzero", "zero"):
            calldata = run(
                [
                    "cast", "calldata", SIG, str(scheme_id), STEALTH,
                    blob(epk_len, fill), blob(meta_len, fill),
                ]
            ).strip()
            gas = send(url, announcer, calldata)
            tokens, zero, nonzero = tokens_of(calldata)
            row[fill] = {
                "calldata_bytes": len(calldata) // 2 - 1,
                "zero_bytes": zero,
                "nonzero_bytes": nonzero,
                "tokens": tokens,
                "total_gas": gas,
                "floor_gas": INTRINSIC + 10 * tokens,
            }

        # Pass 2: derive. `execution` comes from the zero probe, whose floor never
        # binds -- `check()` fails if that stops being true -- so everything above
        # intrinsic and calldata there IS execution.
        z = row["zero"]
        execution = z["total_gas"] - INTRINSIC - 4 * z["tokens"]
        for fill in ("nonzero", "zero"):
            v = row[fill]
            standard = INTRINSIC + 4 * v["tokens"] + execution
            v["floor_binds"] = v["floor_gas"] > standard
            # Charged execution, which is zero where the floor binds -- that is the
            # whole point of the floor. The measured figure lives under `zero`.
            v["execution_gas"] = None if v["floor_binds"] else execution
        z["execution_gas"] = execution

        results.append(row)
    return results


def check(results):
    """Every assumption this harness makes, tested against the measurements."""
    problems = []
    # The case list came from `derive_sizes`, so it agrees with §6 by construction -- but a
    # refactor could break the import and leave a plausible list behind, so the agreement is
    # asserted rather than assumed. Rule #54: a figure re-derived from the constant that
    # produced it proves only that copying worked.
    for r in results:
        if r["schemeId"] == 1:
            continue
        want = derive_sizes.ANNOUNCE_ERC.get(r["name"])
        if want is None:
            problems.append(f"{r['name']}: not a row of derive_sizes.ANNOUNCE_ERC, so its "
                            f"lengths are unchecked against §6")
        elif want[1] != r["payload_bytes"]:
            problems.append(f"{r['name']}: measured a {r['payload_bytes']} B payload where §6 "
                            f"specifies {want[1]} B")
    for r in results:
        nz, z = r["nonzero"], r["zero"]

        # The probe must escape the floor, or it teaches us nothing.
        if z["floor_binds"]:
            problems.append(f"{r['name']}: zero-payload probe still hit the floor")
            continue

        # THE VALIDATION. Where execution is recoverable from both variants they
        # must agree, which is what licenses reading execution off the probe on
        # the rungs where only the probe escapes the floor.
        if not nz["floor_binds"]:
            if nz["execution_gas"] != z["execution_gas"]:
                problems.append(
                    f"{r['name']}: execution differs by payload VALUE "
                    f"({nz['execution_gas']} nonzero vs {z['execution_gas']} zero) "
                    "-- the probe is invalid, do not trust its execution figures"
                )

        # Independent re-derivation of the receipt from the protocol rule (#54).
        execution = z["execution_gas"]
        standard = INTRINSIC + 4 * nz["tokens"] + execution
        predicted = max(standard, nz["floor_gas"])
        if predicted != nz["total_gas"]:
            problems.append(
                f"{r['name']}: EIP-7623 rule predicts {predicted}, "
                f"receipt says {nz['total_gas']}"
            )
    return problems


def table(results):
    base = next(r for r in results if r["schemeId"] == 1)["nonzero"]["total_gas"]
    lines = [
        "",
        "Announcement cost as a REAL STANDALONE TRANSACTION (anvil, --hardfork prague)",
        "",
        f"{'scheme':<38}{'payload':>9}{'calldata':>10}{'exec':>8}"
        f"{'TOTAL':>10}{'floor?':>8}{'x class':>9}",
        "-" * 92,
    ]
    for r in results:
        nz, z = r["nonzero"], r["zero"]
        lines.append(
            f"{r['name']:<38}{r['payload_bytes']:>9}{nz['calldata_bytes']:>10}"
            f"{z['execution_gas']:>8}{nz['total_gas']:>10}"
            f"{('YES' if nz['floor_binds'] else 'no'):>8}"
            f"{nz['total_gas'] / base:>8.2f}x"
        )
    lines += [
        "-" * 92,
        "TOTAL is off the receipt and includes the 21 000 intrinsic and all calldata.",
        "exec is from the all-zero probe; where the floor binds it is NOT CHARGED.",
        "",
    ]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc-url", help="use a running node instead of booting anvil")
    ap.add_argument("--json", action="store_true", help="rewrite measured.json")
    args = ap.parse_args()

    for tool in ("cast", "forge"):
        if not shutil.which(tool):
            sys.exit(f"{tool} not found on PATH (install Foundry)")
    if not args.rpc_url and not shutil.which("anvil"):
        sys.exit("anvil not found on PATH; pass --rpc-url to use a running node")

    node = Node(args.rpc_url)
    try:
        announcer = deploy(node.url)
        results = measure(node.url, announcer)
    finally:
        node.close()

    problems = check(results)
    print(table(results))
    if problems:
        print("SELF-CHECK FAILED:")
        for p in problems:
            print("  ! " + p)
    else:
        print("self-check: OK (probe validated on the two non-floor rungs; "
              "every receipt re-derived from the EIP-7623 rule)")

    if args.json:
        out = {
            "harness": "announcement",
            "what": "total transaction gas for one ERC-5564 announce(), by scheme; "
                    "the schemeId 6 rows are nonconforming wire-shape probes "
                    "(schemeId 2 stand-in address, see the stand-in note on STEALTH)",
            "hardfork": "prague",
            "intrinsic_gas": INTRINSIC,
            "self_check": "pass" if not problems else problems,
            "cases": results,
            # Same rows keyed by name, so `contracts/test/AnnouncementGas.t.sol`
            # can address them without depending on list order.
            "cases_by_name": {r["name"]: r for r in results},
        }
        (HERE / "measured.json").write_text(json.dumps(out, indent=2) + "\n")
        print(f"wrote {HERE / 'measured.json'}")

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
