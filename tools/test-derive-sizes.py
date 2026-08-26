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
    case("it states the FIPS 204 packing widths it derives from",
         "t1: 10 bits/coeff" in out and "t0: 13 bits/coeff" in out, True)

    print("\na quoted figure that disagrees with the derivation")
    # The defect this whole file exists because of: §4.2 said 3 104 at category 3, which is
    # the `t1`-only total. If the quoted figure moves, the tool must say so.
    rc, out = run(("SPEC_META = {2: 4_128, 3: 5_600, 5: 7_072}",
                   "SPEC_META = {2: 4_128, 3: 3_104, 5: 7_072}"))
    case("a wrong meta-address figure exits 1", rc, 1)
    case("and names the category and both numbers",
         "category 3" in out and "5600" in out and "3104" in out, True)

    rc, out = run(("SPEC_ANNOUNCEMENT = {2: 2_376, 3: 3_016, 5: 3_656}",
                   "SPEC_ANNOUNCEMENT = {2: 2_376, 3: 3_017, 5: 3_656}"))
    case("a wrong announcement payload exits 1", rc, 1)
    case("and names the announcement figure", "3017" in out, True)

    rc, out = run(('"schemeId 2 announcement":  (CT + VIEW_TAG,                       1_096)',
                   '"schemeId 2 announcement":  (CT + VIEW_TAG,                       1_095)'))
    case("a wrong schemeId 2 payload exits 1", rc, 1)
    case("and names schemeId 2", "schemeId 2 announcement" in out, True)
    # The ANNOUNCE_ERC loop and the SHAPES loop both compare a total against the same quoted
    # figure, so either alone catches a wrong quote -- and that redundancy once made the
    # mutation deleting ANNOUNCE_ERC's `bad.append` SURVIVE this suite. Each loop's message
    # is asserted separately below, so each append is individually observable. A guard nothing
    # can distinguish from its neighbour is a guard nobody notices losing.
    case("and it is the ANNOUNCE_ERC loop that says so", "derived 1096 != quoted 1095" in out,
         True)
    case("and the SHAPES loop says so too, in its own words",
         "totals 1096 != §6's 1095" in out, True)

    print("\nthe shape table -- (ephemeralPubKey, metadata), not the total")
    rc, out = run(('    "schemeId 4 first contact": (0,                VIEW_TAG + CT),',
                   '    "schemeId 4 first contact": (1,                VIEW_TAG + CT),'))
    case("a shape whose fields do not total the quoted payload exits 1", rc, 1)
    case("and names the shape", "shape (1, 1096) totals 1097" in out, True)

    # Two rows sharing a shape is legal and declared; a THIRD collision appearing quietly is
    # what this catches. §6's note about recognition would go stale and nothing else would say
    # so, because both rows would still total correctly.
    rc, out = run(('    "schemeId 2 announcement":  (CT,               VIEW_TAG),',
                   '    "schemeId 2 announcement":  (0,                VIEW_TAG + CT),'))
    case("an undeclared shape collision exits 1", rc, 1)
    case("and names both rows", "UNDECLARED shape collision" in out
         and "schemeId 4 first contact" in out, True)

    rc, out = run(('DECLARED_SHAPE_COLLISIONS = [("schemeId 3 announcement", "schemeId 5 first contact")]',
                   'DECLARED_SHAPE_COLLISIONS = [("schemeId 2 announcement", "schemeId 4 first contact")]'))
    case("a declared collision that is not one exits 1", rc, 1)
    case("and says the two are not the same shape", "the same shape and they are" in out, True)

    rc, out = run(('"schemeId 2": (SPENDING_PK + EK,                   1_217)',
                   '"schemeId 2": (SPENDING_PK + EK,                   1_218)'))
    case("a wrong meta-address for schemeIds 2 to 5 exits 1", rc, 1)
    case("and names it as a meta-address", "meta-address" in out, True)

    print("\nthe registration ratios added with §7's table")
    # A SELF-CONSISTENT wrong pair: the baseline and the ratio agree with each other and the
    # baseline is not the largest of schemeIds 2 to 5. This is the classic comparison
    # defect in miniature —
    # 5 600 / 1 217 is 4.6, which is arithmetically fine and answers the wrong question.
    rc, out = run(("LARGEST_2_TO_5 = 1_250", "LARGEST_2_TO_5 = 1_217"),
                  ('VS_LARGEST_2_TO_5 = "4.5"', 'VS_LARGEST_2_TO_5 = "4.6"'))
    case("a self-consistent wrong baseline exits 1", rc, 1)
    case("and the finding says which figure the baseline should have been",
         "1250" in out and "1217" in out, True)

    rc, out = run(('"6, category 3": (5_600, "84.8")', '"6, category 3": (5_600, "84.9")'))
    case("a wrong registration ratio exits 1", rc, 1)
    case("and names the schemeId and both ratios",
         "6, category 3" in out and "84.8" in out and "84.9" in out, True)

    rc, out = run(("T0_GROWTH_PCT = 80", "T0_GROWTH_PCT = 79"))
    case("a wrong t0-growth percentage exits 1", rc, 1)
    case("and names the derived and quoted percentages",
         "80%" in out and "79%" in out, True)

    print("\nthe reference implementation's constants are asserted, not trusted")
    rc, out = run(("SPIRIT_POC_POLYT0_PACKEDBYTES = 416",
                   "SPIRIT_POC_POLYT0_PACKEDBYTES = 417"))
    case("a disagreeing implementation constant exits 1", rc, 1)
    case("and says which constant", "POLYT0" in out or "t0" in out, True)

    print("\nthe withdrawn figures are reproduced, so the defect stays falsifiable")
    rc, out = run(("SUPERSEDED_META = {2: 2_464, 3: 3_104, 5: 3_744}",
                   "SUPERSEDED_META = {2: 2_464, 3: 3_105, 5: 3_744}"))
    case("a withdrawn figure that is not the t1-only total exits 1", rc, 1)
    case("and shows the arithmetic it failed to reproduce",
         "3104" in out or "3105" in out, True)

    print("\nthe derivation side")
    # If the sum stops including t0, the corrected figures stop being reachable -- which is
    # the original defect, reintroduced. The tool must fail rather than agree with itself.
    rc, out = run(("        total = t1 + t0 + EK", "        total = t1 + EK"))
    case("dropping t0 from the sum exits 1", rc, 1)
    case("and the failure is on the meta-address, not the announcement",
         "meta-address" in out or "category 3" in out, True)

    # The formula must agree with the implementation constant it is checked against, and
    # that cross-check is the only thing distinguishing "derived" from "copied" here.
    rc, out = run(("EK = 384 * MLKEM_768_K + 32", "EK = 384 * MLKEM_768_K + 33"))
    case("a KEM key length disagreeing with the implementation exits 1", rc, 1)
    case("and names both lengths", "1185" in out and "1184" in out, True)

    # A prior form of the case here substituted the literal 10 for `Q_BITS - D` and
    # assert exit 0, which proves nothing about the "derived from FIPS 204" claim and READS
    # as coverage of it. Substituting an equal value is inert. What is testable is that the
    # FIPS PARAMETERS are load-bearing: change one and every total must move.
    rc, out = run(("D = 13", "D = 12"))
    case("changing FIPS 204's d exits 1", rc, 1)
    case("and the failure is on the meta-address totals",
         "meta-address" in out or "category 3" in out, True)
    # Isolating: `d` must reach BOTH widths. `t1` is `Q_BITS - d` so it moves either way,
    # but `t0` is `d` itself — and a hardcoded `T0_BITS_PER_COEFF = 13` is inert against
    # every assertion above, because the totals move on `t1` alone.
    case("and d reaches t0's width, not only t1's",
         "12 bits/coeff x 256 = 384 B/poly" in out, True)

    rc, out = run(("Q = 8_380_417", "Q = 4_190_209"))
    case("changing FIPS 204's q exits 1", rc, 1)
    case("and it moves t1's width, which the output prints",
         "bits/coeff" in out, True)

    rc, out = run(("MLKEM_768_K = 3", "MLKEM_768_K = 2"))
    case("changing FIPS 203's k exits 1", rc, 1)
    case("and the failure names the KEM key length", "1184" in out or "ek" in out, True)

    # The widths are printed as arithmetic, so a reader can check them against FIPS 204
    # Table 1 without running anything -- which is the only defence against a derivation that
    # is wrong in the same way its cross-check is.
    rc, out = run()
    case("the packing widths print as arithmetic, not as results",
         "10 bits/coeff x 256 = 320 B/poly" in out
         and "13 bits/coeff x 256 = 416 B/poly" in out, True)

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: derive_sizes behaves as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
