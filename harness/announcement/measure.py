#!/usr/bin/env python3
"""Announcement cost, measured as real standalone transactions.

    python3 measure.py                # boots its own anvil, prints the table
    python3 measure.py --json         # rewrites measured.json
    python3 measure.py --rpc-url URL  # against an already-running node

Needs `anvil`, `cast` and `forge` on PATH; `forge` builds the announcer from
`../../contracts`. Exits 1 if any self-check fails.

WHAT EACH CONVENTION IS AND WHY IT MOVES THE NUMBER IS STATED HERE, at the point the
convention is applied, and is deliberately NOT repeated in `README.md`. It used to be in
both places: the two copies drifted, and every stale claim this directory has carried was
carried twice. One home, and this is it -- the reader who needs a convention is reading
the code that applies it.
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
# `tools/derive_sizes.py` already owns these lengths, re-derives them from FIPS 203
# rather than from any constant that produced them, and asserts them against §6. Reading them
# from there means a wire change cannot leave the gas figures measuring a payload the document
# no longer specifies -- the failure mode a moving wire model makes routine.
sys.path.insert(0, str(ROOT / "tools"))
import derive_sizes  # noqa: E402

# The EVM the receipts are taken against. anvil's default would silently reprice everything
# on a Foundry bump, so it is passed explicitly, and it is one constant rather than the three
# separate string literals it used to be.
HARDFORK = "prague"

# What the announcer must be built with. `contracts/foundry.toml` DECLARES these; the check
# below asserts what the build ACTUALLY used, which is the pair that can disagree -- a machine
# with a different solc on PATH, a profile override, a stale artifact.
#
# WHY PIN AT ALL, measured rather than assumed: `harness/registration` prices the registry's
# DEPLOYED bytecode, so no compiler setting can reach it; this announcer is a local build, so
# every one of them does. Turn the optimizer off and change nothing else and the classical
# baseline's execution goes 5 143 -> 6 471, its TOTAL 28 067 -> 29 395, and the published ratio
# 2.47x -> 2.36x. The classical row is the denominator and the one row the EIP-7623 floor does
# not cover, so the whole shift lands there.
#
# `EVM_VERSION` must equal `HARDFORK`: solc targeting one EVM while anvil executes another is
# a measurement of neither, and nothing else in this file would notice.
SOLC_VERSION = "0.8.28"
OPTIMIZER = {"enabled": True, "runs": 200}
EVM_VERSION = HARDFORK

# anvil's first default account. Public, published in anvil's own banner.
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# A REAL derived stealth address, not a decorative constant.
#
# NOT `0x0000000000000000000000000000000000C0FFEE`: cute, and **three
# nonzero bytes where a real address has twenty**. Under EIP-7623 a zero calldata byte costs one
# token and a nonzero one costs four, and on every post-quantum scheme the floor binds -- so the
# decorative address made each of those rows cheaper than the transaction it claimed to price, by
# 51 tokens and therefore **510 gas**.
#
# A second harness measuring the same transaction with a real address disagrees by 480:
# the arithmetic is right, the FIXTURE is not, and a fixture chosen
# for looks is a fixture nobody checks. A ratio computed against it understated the cost of every scheme the floor
# binds on, which is all of them except the classical baseline.
#
# The value was derived by the KEM-only scheme that this single-scheme export does not
# carry, from the demonstration seed -- an output of a scheme rather than a number someone
# typed. That provenance CANNOT BE REPRODUCED HERE, and saying so is the point: what the
# constant is relied on for is its byte distribution, which is checkable from the value
# itself and is asserted below, not its lineage, which is not.
STEALTH = "0x6dbb67f21b650304b5f459833188f52db07c2b43"
# The property every row actually depends on, checked rather than described: twenty bytes, and
# a zero-byte count a real address plausibly has (a random one carries none about 92% of the
# time). Under EIP-7623 each zero byte is three tokens cheaper, so a fixture drifting toward
# zeros silently cheapens every row -- which is precisely what the decorative address did.
_STEALTH_BYTES = bytes.fromhex(STEALTH[2:])
assert len(_STEALTH_BYTES) == 20 and _STEALTH_BYTES.count(0) <= 1, (
    f"STEALTH must be a byte-realistic 20-byte address: got {len(_STEALTH_BYTES)} bytes "
    f"with {_STEALTH_BYTES.count(0)} zero byte(s)")
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

    Order: the classical baseline first, then the rest in `schemeId` order, so the printed
    table reads the way §6's does.
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
    """Payload bytes, in the two fills every row is measured with.

    `fill='nonzero'` reproduces the pattern the Foundry fixture used
    (`1 + i % 255`, never zero) so the token count is the worst case.

    `fill='zero'` is THE EXECUTION PROBE, and it is the whole reason `execution` can be
    reported at all. Where the EIP-7623 floor binds, the transaction pays
    `21000 + 10*tokens` whatever the EVM actually did, so execution is not on the receipt
    and cannot be subtracted back out of it.

    The probe exploits an asymmetry between the two charges. Execution is a function of
    calldata LENGTH -- LOG data is 8/byte whatever the byte is, and memory expansion and
    `CALLDATACOPY` are length-driven. The EIP-7623 token count is a function of calldata
    VALUES -- a zero byte is 1 token, a nonzero byte is 4. So the same call at the same
    length with an all-zero payload executes identically and costs about four times fewer
    tokens, which drops it off the floor and exposes execution as
    `total - 21000 - 4*tokens`.

    That the two fills execute identically is an ASSUMPTION, so `check()` tests it rather
    than trusting it: the probe must escape the floor on every row, and on every row where
    the nonzero variant also escapes, the two execution figures must agree exactly.
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
            ["anvil", "--hardfork", HARDFORK, "--port", str(port), "--silent"],
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


def toolchain():
    """What the announcer was ACTUALLY built with. Raises rather than repricing quietly."""
    raw = run(["forge", "inspect", "ERC5564Announcer", "metadata",
               "--root", str(CONTRACTS), "--json"])
    md = json.loads(raw)
    if isinstance(md, str):                     # forge has emitted the JSON as a JSON string
        md = json.loads(md)
    version = md["compiler"]["version"]
    optimizer = md["settings"]["optimizer"]
    evm = md["settings"].get("evmVersion")
    bad = []
    if not version.startswith(SOLC_VERSION + "+"):
        bad.append(f"solc {version}, expected {SOLC_VERSION}")
    if {"enabled": optimizer.get("enabled"), "runs": optimizer.get("runs")} != OPTIMIZER:
        bad.append(f"optimizer {optimizer}, expected {OPTIMIZER}")
    if evm != EVM_VERSION:
        bad.append(f"solc targeted evmVersion {evm}, expected {EVM_VERSION} to match the "
                   f"hardfork anvil runs")
    if bad:
        sys.exit("TOOLCHAIN MISMATCH -- the execution figures would not be the committed "
                 "ones, and the receipt would not say so:\n  " + "\n  ".join(bad))
    return {"solc": version, "optimizer": {"enabled": optimizer["enabled"],
                                           "runs": optimizer["runs"]},
            "evm_version": evm}


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

        # Pass 1: send, and record only what the receipt says. Every row sends the
        # same STEALTH constant -- see the note on it for why a real derived address
        # rather than a decorative one.
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
        # the schemes where only the probe escapes the floor.
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
        f"Announcement cost as a REAL STANDALONE TRANSACTION (anvil, --hardfork "
        f"{HARDFORK})",
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

    tc = toolchain()

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
        n_val = sum(1 for r in results if not r["nonzero"]["floor_binds"])
        print(f"self-check: OK (probe validated on the {n_val} row(s) where the floor "
              f"binds on neither variant; every receipt re-derived from the EIP-7623 rule)")

    if args.json:
        out = {
            "harness": "announcement",
            "what": "total transaction gas for one ERC-5564 announce(), by scheme, "
                    "each row sending the same real derived stealth address (see the "
                    "note on STEALTH in measure.py)",
            "hardfork": HARDFORK,
            # The announcer is BUILT here rather than read off chain, so the execution
            # figures depend on this as much as on the hardfork. What the optimizer alone
            # is worth is measured beside the constants above.
            "toolchain": tc,
            "intrinsic_gas": INTRINSIC,
            "self_check": "pass" if not problems else problems,
            "cases": results,
            # Same rows keyed by name, so a consumer can address them without depending
            # on list order.
            "cases_by_name": {r["name"]: r for r in results},
        }
        (HERE / "measured.json").write_text(json.dumps(out, indent=2) + "\n")
        print(f"wrote {HERE / 'measured.json'}")

    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
