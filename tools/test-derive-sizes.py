#!/usr/bin/env python3
"""Self-test for the size-derivation harness.

`derive_sizes.py` is the harness rule #54 asks for: no figure in a document without a
committed generator. For a stretch it had no self-test and no mutation coverage, which
means the tool that exists to make numbers falsifiable was itself unfalsifiable — its
"OK: every figure re-derives" line was a green self-report of exactly the kind this suite
treats as no evidence at all.

It takes no input, so the cases work the only way they can: copy the tool, change ONE
quoted figure or ONE derivation, and require it to say which figure disagrees and exit 1.
A tool that reports MISMATCH somewhere but names nothing would pass a bare exit-code check
and tell a reader nothing, so every positive case asserts the name as well.

Exit 0 clean, 1 on any failure.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "derive_sizes.py"
SRC = TOOL.read_text(encoding="utf-8")
FAILED: list[str] = []


def run(*edits: tuple[str, str]) -> tuple[int, str]:
    """Run the tool with `edits` applied to its source. No edits = run it as committed."""
    text = SRC
    for old, new in edits:
        assert old in text, f"anchor absent from derive_sizes.py: {old!r}"
        patched = text.replace(old, new, 1)
        assert patched != text, f"edit was a no-op: {old!r}"
        text = patched
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "derive_sizes.py"
        p.write_text(text, encoding="utf-8")
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr


def case(name: str, got, want) -> None:
    if got == want:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}\n          want: {want!r}\n          got:  {got!r}")
        FAILED.append(name)


def main() -> int:
    print("derive_sizes self-test")

    print("\nthe committed tree")
    rc, out = run()
    case("the tool passes as committed", rc, 0)
    case("and says what it does not cover", "does NOT sweep the documents" in out, True)
    case("it prints the KEM lengths as arithmetic, not as results",
         "384*3 + 32" in out and "32*(10*3 + 4)" in out, True)

    print("\na quoted payload that disagrees with its construction")
    rc, out = run(('"schemeId 3 announcement":  (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122)',
                   '"schemeId 3 announcement":  (SEC1_COMPRESSED + VIEW_TAG + CT,     1_121)'))
    case("a wrong payload exits 1", rc, 1)
    case("and names the row", "schemeId 3 announcement" in out, True)
    # The ANNOUNCE_ERC loop and the SHAPES loop both compare a total against the same quoted
    # figure, so either alone catches a wrong quote -- and that redundancy once made the
    # mutation deleting ANNOUNCE_ERC's `bad.append` SURVIVE this suite. Each loop's message
    # is asserted separately below, so each append is individually observable. A guard nothing
    # can distinguish from its neighbour is a guard nobody notices losing.
    case("and it is the ANNOUNCE_ERC loop that says so", "derived 1122 != quoted 1121" in out,
         True)
    case("and the SHAPES loop says so too, in its own words",
         "totals 1122 != §5's 1121" in out, True)

    print("\nthe view-tag width is load-bearing, and reaches EVERY payload")
    # The failure this case exists for actually happened: the width moved in one file and
    # nothing downstream did. A width that can change while every quoted total still agrees
    # is a width nothing checks.
    rc, out = run(("VIEW_TAG = 1  ", "VIEW_TAG = 8  "))
    case("widening the view tag exits 1", rc, 1)
    case("the ANNOUNCE_ERC loop names the new total",
         "schemeId 3 announcement: derived 1129 != quoted 1122" in out, True)
    case("the SHAPES loop names the new field pair",
         "shape (33, 1096) totals 1129 != §5's 1122" in out, True)

    print("\nthe shape table -- (ephemeralPubKey, metadata), not the total")
    rc, out = run(('    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),',
                   '    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT + 1),'))
    case("a shape whose fields do not total the quoted payload exits 1", rc, 1)
    case("and names the shape", "shape (33, 1090) totals 1123" in out, True)

    # Two rows sharing a shape is legal ONLY if declared; one appearing quietly is what this
    # catches. §5's recognition rule would go stale and nothing else would say so. One scheme
    # ships, so the mutation adds the second -- the detector is what a future scheme walks into.
    ADD = ('    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),\n',
           '    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),\n'
           '    "a second scheme":            (SEC1_COMPRESSED,  VIEW_TAG + CT),\n')
    QUOTE = ('    "schemeId 3 announcement":  (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122),\n',
             '    "schemeId 3 announcement":  (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122),\n'
             '    "a second scheme":            (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122),\n')
    rc, out = run(QUOTE, ADD)
    case("an undeclared shape collision exits 1", rc, 1)
    case("and names both rows", "UNDECLARED shape collision" in out
         and "schemeId 3 announcement" in out and "a second scheme" in out, True)

    rc, out = run(QUOTE,
                  ('    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),\n',
                   '    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),\n'
                   '    "a second scheme":            (CT,               VIEW_TAG),\n'),
                  ("DECLARED_SHAPE_COLLISIONS: list[tuple[str, str]] = []",
                   'DECLARED_SHAPE_COLLISIONS = [("schemeId 3 announcement", '
                   '"a second scheme")]'))
    case("a declared collision that is not one exits 1", rc, 1)
    case("and says the two are not the same shape", "the same shape and they are" in out, True)

    print("\nthe meta-addresses and the registration ratios")
    rc, out = run(('"schemeId 3": (SPENDING_PK + VIEWING_PK_EC + EK,   1_250)',
                   '"schemeId 3": (SPENDING_PK + VIEWING_PK_EC + EK,   1_251)'))
    case("a wrong meta-address exits 1", rc, 1)
    case("and names it as a meta-address", "meta-address" in out, True)

    rc, out = run(('"3": (1_250, "18.9")', '"3": (1_250, "18.8")'))
    case("a wrong registration ratio exits 1", rc, 1)
    case("and names the schemeId and both ratios",
         "18.9" in out and "18.8" in out, True)

    # The figure this replaced -- "a few hundred gas" -- survived being re-pointed at a
    # payload five times smaller than the one it was calibrated for, because prose carries no
    # check. These cases are what make the replacement falsifiable rather than merely newer.
    rc, out = run(('REGISTRATION_OVERSTATEMENT = {"1": 3, "3": 59}',
                   'REGISTRATION_OVERSTATEMENT = {"1": 3, "3": 300}'))
    case("a documented overstatement that is not the derived one exits 1", rc, 1)
    case("and names both", "59" in out and "300" in out, True)

    # The EIP-7623 side of it, which is where the 12 comes from. If the token prices stop
    # being load-bearing the figure is a constant wearing a derivation.
    rc, out = run(("EIP_7623_TOKENS_PER_ZERO_BYTE = 1", "EIP_7623_TOKENS_PER_ZERO_BYTE = 2"))
    case("a wrong zero-byte token price exits 1", rc, 1)
    case("and the derived overstatement moves with it", "~  39 gas" in out, True)

    # And the odds, which are the other input.
    rc, out = run(("ZERO_BYTE_ODDS = 256", "ZERO_BYTE_ODDS = 128"))
    case("wrong odds for a zero byte exit 1", rc, 1)
    case("and the derived overstatement doubles", "~ 117 gas" in out, True)

    print("\nthe delegation window counts -- (len - 32 + 1), not (len / 32)")
    # The scan is over the WHOLE delegated object. `96 / 32 = 3` is the wrong answer that
    # placed the spending seed verbatim in the bytes handed to a scanning service.
    rc, out = run(("(96 - SCALAR + 1, 65)", "(96 // SCALAR, 65)"))
    case("a per-32-byte-block window count exits 1", rc, 1)
    case("and names the window count", "windows" in out, True)

    print("\nthe derivation side -- formulas, not copied constants")
    # The formula must agree with FIPS 203's stated length, and that cross-check is the only
    # thing distinguishing "derived" from "copied" here.
    rc, out = run(("EK = 384 * MLKEM_768_K + 32", "EK = 384 * MLKEM_768_K + 33"))
    case("a KEM key length disagreeing with FIPS 203 exits 1", rc, 1)
    case("and names both lengths", "1185" in out and "1184" in out, True)

    rc, out = run(("CT = 32 * (MLKEM_768_DU * MLKEM_768_K + MLKEM_768_DV)",
                   "CT = 32 * (MLKEM_768_DU * MLKEM_768_K + MLKEM_768_DV) + 1"))
    case("a ciphertext length disagreeing with FIPS 203 exits 1", rc, 1)
    case("and names both lengths", "1089" in out and "1088" in out, True)

    # FIPS 203's parameters must be load-bearing: change one and the lengths must move.
    rc, out = run(("MLKEM_768_K = 3", "MLKEM_768_K = 2"))
    case("changing FIPS 203's k exits 1", rc, 1)
    case("and the EK guard names both lengths",
         "ek 800 != FIPS 203's 1184" in out, True)

    rc, out = run(("MLKEM_768_DU = 10", "MLKEM_768_DU = 11"))
    case("changing FIPS 203's du exits 1", rc, 1)
    case("and it moves the ciphertext, which every payload is built on",
         "1088" in out, True)

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: derive_sizes behaves as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
