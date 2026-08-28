#!/usr/bin/env python3
"""Self-test for the gas-receipt verifier.

`check_measured.py` is a STALENESS gate: it re-derives every committed receipt from EIP-7623 and
checks every payload against §6's wire table, without a node. So the cases here are the ways a
stale or wrong file could slip past it -- not the ways it could be noisy.

Exit 0 clean, 1 on any failure.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "check_measured.py"
FAILED: list[str] = []

# The fixture is SYNTHESISED here rather than read from `harness/announcement/measured.json`.
#
# This suite also runs from temp trees that carry only the tool under test, so a
# suite that reaches for the real measurements dies on a missing path and reports INCONCLUSIVE
# for all five of its mutations -- which is worse than a failure, because it means the guard was
# never exercised and the report said so only in a word a reader might skim past.
#
# Synthesising it also makes the cases independent of what the real numbers happen to be:
# re-running the harness should not change what this suite proves.


def synthetic() -> dict:
    """A self-consistent measurement set: every row of §6's table, plus schemeId 1.

    Gas is computed from EIP-7623 rather than invented, because a fixture that did not satisfy
    the rule would make every case below fail for the wrong reason.
    """
    sys.path.insert(0, str(TOOL.parent))
    import derive_sizes

    cases = []

    def row(name: str, scheme_id: int, epk: int, md: int) -> dict:
        payload = epk + md
        # A plausible ABI calldata length: selector, two offsets, two length words, padded data.
        calldata = 4 + 32 * 3 + 32 * ((epk + 31) // 32 + 1) + 32 * ((md + 31) // 32 + 1)
        nonzero = payload
        zero = calldata - nonzero
        tokens = zero + 4 * nonzero
        zero_tokens = calldata
        execution = 5000 + 8 * calldata
        return {
            "name": name,
            "schemeId": scheme_id,
            "epk_bytes": epk,
            "metadata_bytes": md,
            "payload_bytes": payload,
            "nonzero": {
                "calldata_bytes": calldata,
                "tokens": tokens,
                "total_gas": max(21_000 + 4 * tokens + execution, 21_000 + 10 * tokens),
                "floor_gas": 21_000 + 10 * tokens,
                "floor_binds": 21_000 + 10 * tokens > 21_000 + 4 * tokens + execution,
            },
            "zero": {
                "calldata_bytes": calldata,
                "tokens": zero_tokens,
                "total_gas": 21_000 + 4 * zero_tokens + execution,
                "floor_gas": 21_000 + 10 * zero_tokens,
                "floor_binds": False,
                "execution_gas": execution,
            },
        }

    cases.append(row("classical (ERC-5564 schemeId 1)", 1, 33, 1))
    for name, (epk, md) in derive_sizes.SHAPES.items():
        cases.append(row(name, derive_sizes.SHAPE_SCHEME_ID[name], epk, md))
    return {
        "harness": "announcement",
        "hardfork": "prague",
        "intrinsic_gas": 21_000,
        "self_check": "pass",
        "cases": cases,
    }


def case(name: str, got, want) -> None:
    if got == want:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}\n          want: {want!r}\n          got:  {got!r}")
        FAILED.append(name)


def run_with_audit(data: dict, text: str) -> tuple[int, str]:
    """Run the tool against a tree whose AUDIT.md holds `text` -- the non-docs sweep, where
    the gas-proximity window applies. Separate from `run_with_doc` because the two sweeps
    have different scope rules and a case must say which one it exercises."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        (root / "AUDIT.md").write_text(text, encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(TOOL), str(root)], capture_output=True, text=True
        )
        return r.returncode, r.stdout + r.stderr


def run_with_doc(data: dict, doc_text: str, name: str = "scheme-2.md") -> tuple[int, str]:
    """Run the tool against a tree that also holds `docs/<name>` with `doc_text`.

    The prose sweep is a gate over the `docs` directory, so it needs a tree with a doc in it.
    Kept separate
    from `run` rather than folded in, because every case above asserts behaviour with NO docs
    present and a default doc would make those cases pass for a second reason. The `name`
    parameter exists because the elision exemption is FILE-scoped: a transcript file and an
    ordinary doc must be distinguishable by the case that pins the scope.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        (root / "docs").mkdir()
        (root / "docs" / name).write_text(doc_text, encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(TOOL), str(root)], capture_output=True, text=True
        )
        return r.returncode, r.stdout + r.stderr


def run(data: dict) -> tuple[int, str]:
    """Run the tool against a tree holding `data` as the measurements.

    The real `tools/` is symlinked in, because the tool imports `derive_sizes` from beside
    itself -- so a temp tree needs the real one to compare §6's lengths against.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        r = subprocess.run(
            [sys.executable, str(TOOL), str(root)], capture_output=True, text=True
        )
        return r.returncode, r.stdout + r.stderr


def main() -> int:
    print("check_measured self-test")
    real = synthetic()

    print("\na self-consistent measurement set")
    rc, out = run(real)
    case("a rule-satisfying file passes", rc, 0)
    case("and says every receipt re-derives", "re-derives from EIP-7623" in out, True)
    case("and reports which rule applied per row", out.count("floor") >= 6, True)

    print("\na receipt that does not follow the rule FAILS")
    d = copy.deepcopy(real)
    d["cases"][1]["nonzero"]["total_gas"] += 1
    rc, out = run(d)
    case("a total off by one exits 1", rc, 1)
    case("and names the row and both figures", "EIP-7623 predicts" in out, True)

    print("\na PAYLOAD that no longer matches §6 FAILS -- the staleness this exists for")
    d = copy.deepcopy(real)
    d["cases"][1]["payload_bytes"] = 1096   # the superseded eight-byte-tag payload
    rc, out = run(d)
    case("a superseded payload exits 1", rc, 1)
    case("and says the wire changed and the receipt did not",
         "the wire changed and this receipt did not" in out, True)

    print("\nfield lengths are checked too, not just the total")
    d = copy.deepcopy(real)
    d["cases"][1]["epk_bytes"] = 1080
    d["cases"][1]["metadata_bytes"] = 9
    rc, out = run(d)
    case("a wrong field split exits 1", rc, 1)
    case("and names §6's split", "where §6 gives" in out, True)

    print("\na MISSING row fails -- §7 must not have a silent gap")
    d = copy.deepcopy(real)
    d["cases"] = [c for c in d["cases"] if c["name"] != "memo (schemeIds 4, 5)"]
    rc, out = run(d)
    case("dropping a row exits 1", rc, 1)
    case("and says §6 has the row and nothing measured it",
         "nothing measured it" in out, True)

    print("\nthe harness's own self-check must have passed when the file was written")
    d = copy.deepcopy(real)
    d["self_check"] = ["the probe was invalid"]
    rc, out = run(d)
    case("a failed self-check exits 1", rc, 1)
    case("and says so rather than re-deriving anyway",
         "self-check did not pass" in out, True)

    print("\nthe recorded floor and floor_binds are checked against the rule, not trusted")
    d = copy.deepcopy(real)
    d["cases"][1]["nonzero"]["floor_gas"] += 10
    rc, _ = run(d)
    case("a wrong recorded floor exits 1", rc, 1)
    d = copy.deepcopy(real)
    d["cases"][1]["nonzero"]["floor_binds"] = not d["cases"][1]["nonzero"]["floor_binds"]
    rc, _ = run(d)
    case("a wrong floor_binds exits 1", rc, 1)

    print("\nand the REAL committed file, if this tree has one")
    print("\nthe prose sweep over docs/")
    real_gas = real["cases"][1]["nonzero"]["total_gas"]
    rc, out = run_with_doc(real, f"costs **{real_gas} gas** per announcement.\n")
    case("a figure that IS a receipt passes", rc, 0)
    case("and it is counted", "gas figures quoted in prose" in out, True)

    rc, out = run_with_doc(real, f"costs **{real_gas + 7} gas** per announcement.\n")
    case("a figure that is NOT a receipt exits 1", rc, 1)
    case("and names it unfalsifiable", "unfalsifiable" in out, True)

    # The reason the sweep over the docs directory does not key on the word `gas`: the SECOND
    # operand of a
    # comparison sits outside any keyword window, and a comparison is where a stale figure
    # hides, since a reader checks the ratio and not the operands.
    other = real["cases"][0]["nonzero"]["total_gas"]
    rc, out = run_with_doc(real, f"**{real_gas} gas** against {other + 3}, a clear win.\n")
    case("a bad SECOND operand is caught even with no keyword near it", rc, 1)

    # And the thing that makes the wide sweep survivable: byte counts are not gas, and the
    # exempt set is read off the size model rather than listed, so this passes without anyone
    # registering 1 250 anywhere.
    rc, out = run_with_doc(real, "the registry entry is 1 250 B, and the IKM is 2 402 B.\n")
    case("byte counts from the size model are not treated as gas", rc, 0)

    # An ELIDED HEX TAIL: the demo transcripts print long values as head…tail, and a tail
    # that is all digits -- a small counter in big-endian hex, every time -- is bytes, not a
    # figure. The exclusion requires the HEX-then-ellipsis prefix: the same digits without
    # the elision stay a finding, and so does a bare-ellipsis number in prose -- an
    # approximation mark on an unmeasured figure is exactly what this gate exists to catch,
    # so punctuation must not be a way past it. (The tail here is a real one: a watch
    # record's next=2 ‖ lookahead=20.)
    transcript = "transcripts-scheme-4.md"
    # The exemption's scope is a GENERATED SPAN: an `output-of` marker's fenced body. The
    # tail line is legitimate there and only there.
    tail = "watch record 53 B 03f6b94c…00000000000000000000000200000014"
    in_span = f"# t\n\n<!-- output-of: demo-4 -->\n```text\n{tail}\n```\n"
    rc, out = run_with_doc(real, in_span, transcript)
    case("an elided hex tail INSIDE a generated span is not treated as gas", rc, 0)
    rc, out = run_with_doc(real, f"# t\n\nhand-written: {tail}\n", transcript)
    case("the SAME line in the transcript's hand-written prose IS", rc, 1)
    rc, out = run_with_doc(real, in_span)
    case("and a generated-looking span in an ordinary doc exempts nothing", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-4 -->\n```text\nthe run cost 00000000000000000000000200000014 exactly.\n```\n",
        transcript,
    )
    case("and the same digits without the elision are caught, even inside a span", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-4 -->\n```text\nthe estimated execution cost is …99999 gas.\n```\n",
        transcript,
    )
    case("and a bare-ellipsis figure is too", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-4 -->\n```text\nsums to 01f6b94c…99 999 in that configuration.\n```\n",
        transcript,
    )
    case("and a SPACED figure behind a hex ellipsis is too — hex tails have no spaces", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-4 -->\n```text\nthe preface…99999 gas was the estimate.\n```\n",
        transcript,
    )
    case("and a WORD ending in hex letters exempts nothing even there", rc, 1)
    rc, out = run_with_doc(real, "the deadbee7…99999 gas estimate held.\n")
    case("and a hex-shaped WORD in ordinary prose is caught by the scope", rc, 1)

    print("\na second harness's receipts vouch too, marginal_gas included")
    # The ntt harness prices per-call primitives: its receipts carry `marginal_gas` --
    # a marginal reading, not the total of a sent transaction -- and a collector keyed
    # only on transaction fields would report every ring figure as unfalsifiable on
    # the day it is quoted.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(real), encoding="utf-8")
        (root / "harness/ntt").mkdir(parents=True)
        (root / "harness/ntt/measured.json").write_text(json.dumps({
            "harness": "ntt",
            "cases": [{"name": "forward NTT per polynomial, *Mul (the schemeId 6 ring row)",
                       "marginal_gas": 177_810}],
        }), encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs" / "ring.md").write_text(
            "the forward transform costs **177 810 gas** per polynomial.\n", encoding="utf-8")
        r = subprocess.run([sys.executable, str(TOOL), str(root)],
                           capture_output=True, text=True)
        case("a marginal_gas receipt vouches a quoted figure", r.returncode, 0)
        (root / "docs" / "ring.md").write_text(
            "the forward transform costs **177 811 gas** per polynomial.\n", encoding="utf-8")
        r = subprocess.run([sys.executable, str(TOOL), str(root)],
                           capture_output=True, text=True)
        case("and a figure off by one is still unfalsifiable", r.returncode, 1)

    print("\nusage is FAIL-CLOSED: a typo narrows no sweep")
    # `. --al` is one letter from the scope AUDIT requires; a verifier that silently runs
    # the narrower default on it reports a pass it never earned.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(real), encoding="utf-8"
        )
        r = subprocess.run([sys.executable, str(TOOL), str(root), "--bogus"],
                           capture_output=True, text=True)
        case("an unknown flag AFTER the root exits 2", r.returncode, 2)
        r = subprocess.run([sys.executable, str(TOOL), "--bogus", str(root)],
                           capture_output=True, text=True)
        case("an unknown flag BEFORE the root exits 2", r.returncode, 2)
        r = subprocess.run([sys.executable, str(TOOL), str(root), str(root)],
                           capture_output=True, text=True)
        case("a second positional exits 2", r.returncode, 2)
    # An INLINE marker — one check_examples' anchored grammar never recognises, so its
    # fenced block is never re-run — must confer no exemption: the two parsers sharing one
    # grammar is what makes "generated span" mean "authenticated span".
    rc, out = run_with_doc(
        real,
        f"prefix <!-- output-of: demo-4 -->\n```text\n{tail}\n```\n",
        transcript,
    )
    case("an INLINE marker's block gets no exemption — the grammars are one", rc, 1)

    # OUTSIDE docs/, the gas-proximity window is SYMMETRIC on the line: the word before the
    # number is as good as the word after it. The lookahead-only form was blind to "gas"
    # coming first, and a live, arithmetically false figure sat unexamined behind exactly
    # that. AUDIT.md is the non-docs gas document this harness can synthesise.
    rc, out = run_with_audit(real, "the announcement's gas total came to 99 999 that day.\n")
    case("outside docs/, gas BEFORE a bad figure still catches it", rc, 1)
    rc, out = run_with_audit(real, "a table of 99 999 entries, nothing to do with fees.\n")
    case("and a figure with no gas nearby stays out of scope there", rc, 0)
    # The author's line wrap must not hide the unit word: a wrapped sentence puts "gas"
    # one line from its figure, and a same-line window read the number and never the unit
    # — two live ring figures sat exactly there.
    rc, out = run_with_audit(real, "the forward transform costs 99 999,\ngas per polynomial.\n")
    case("a unit word on the NEXT line still catches the figure", rc, 1)
    rc, out = run_with_audit(real, "measured in gas below.\nthe row lists 99 999 entries\nof metadata, none priced.\n")
    case("and one on the PREVIOUS line does too", rc, 1)
    rc, out = run_with_audit(real, "priced in gas above.\n\nan index of 99 999 entries.\n")
    case("but two lines away, across the wrap, is out of scope", rc, 0)

    # A DERIVED figure: prose comparing two rungs quotes their difference. The prose
    # names the schemes the numbers actually come from (cases[1] is schemeId 2,
    # cases[0] the classical baseline) — a delta attributed to schemes it was not
    # computed from is exactly what the scheme-binding check rejects.
    delta = real_gas - other
    rc, out = run_with_doc(real, f"schemeId 2 costs {delta} more gas than classical.\n")
    case("a difference between two receipts is allowed", rc, 0)
    rc, out = run_with_doc(real, f"schemeId 2 costs {delta + 1} more gas than classical.\n")
    case("but a wrong difference is not", rc, 1)
    # THE BINDING ITSELF, on the reviewer's exact shape: swap two schemes' totals in
    # prose — both numbers are receipts, both claims false, and set membership alone
    # certified them.
    gas2 = real["cases"][1]["nonzero"]["total_gas"]
    gas3 = real["cases"][2]["nonzero"]["total_gas"]
    rc, out = run_with_doc(
        real, f"schemeId 2 costs {gas3:,} gas.\n\nschemeId 3 costs {gas2:,} gas.\n"
              .replace(",", " "))
    case("swapped scheme totals are misassigned receipts, not a pass", rc, 1)
    case("and the finding names the misassignment",
         "assigned to the wrong claim" in out, True)
    rc, out = run_with_doc(
        real, f"schemeId 2 costs {gas2:,} gas.\n\nschemeId 3 costs {gas3:,} gas.\n"
              .replace(",", " "))
    case("the same totals rightly assigned pass", rc, 0)
    # ONE paragraph naming both schemes, totals swapped: under a scope-wide union each
    # figure stays vouched by the OTHER claim's receipt. The binding is to the nearest
    # preceding mention — the claim the figure actually belongs to.
    rc, out = run_with_doc(
        real, f"schemeId 2 costs {gas3:,} gas where schemeId 3 costs {gas2:,} gas.\n"
              .replace(",", " "))
    case("a swap inside one sentence is caught, not vouched by the union", rc, 1)
    rc, out = run_with_doc(
        real, f"schemeId 2 costs {gas2:,} gas where schemeId 3 costs {gas3:,} gas.\n"
              .replace(",", " "))
    case("and the same sentence rightly assigned passes", rc, 0)

    print("\na table's gas column is a gas claim, and its row names its scheme")
    # The reviewer's counterexample verbatim in shape: a README-style ladder table, no
    # scheme named in prose, the unit named only by the column HEADER, totals swapped.
    def ladder(a: int, b: int) -> str:
        return ("## The ladder\n\n"
                "| schemeId | announcement | gas | state |\n"
                "|---|---|---|---|\n"
                f"| **2** | 1 096 B | {a:,} | none |\n"
                f"| **3** | 1 129 B | {b:,} | none |\n").replace(",", " ")
    rc, out = run_with_audit(real, ladder(gas2, gas3))
    case("a rightly assigned ladder table passes", rc, 0)
    rc, out = run_with_audit(real, ladder(gas3, gas2))
    case("the README two-row swap is caught", rc, 1)
    case("and both rows are named",
         out.count("assigned to the wrong claim"), 2)
    # The byte column in the passing table proves its own point: `1 096` matches the
    # figure pattern and is no receipt, and only the header scope keeps it out.
    memo_tot = next(c["nonzero"]["total_gas"] for c in real["cases"]
                    if c["name"] == "memo (schemeIds 4, 5)")
    rc, out = run_with_audit(
        real, ("| schemeId | memo | gas |\n|---|---|---|\n"
               f"| **5** | 8 B | {memo_tot:,} |\n").replace(",", " "))
    case("a receipt naming two schemes vouches for both rows", rc, 0)
    rc, out = run_with_audit(
        real, ("| schemeId | first contact | gas |\n|---|---|---|\n"
               f"| **6** | 1 096 B | {gas2:,} |\n").replace(",", " "))
    case("a scheme's row does not borrow another scheme's receipt", rc, 1)

    print("\na table is a table in every GFM spelling, and a first cell may name two schemes")
    # GFM permits tables without leading/trailing pipes and inside blockquotes; a
    # swap must be caught in each spelling, not only the fully piped one.
    rc, out = run_with_audit(
        real, ("schemeId | announcement | gas\n---|---|---\n"
               f"**2** | 1 096 B | {gas3:,}\n**3** | 1 129 B | {gas2:,}\n")
        .replace(",", " "))
    case("a no-leading-pipe table's swap is caught", rc, 1)
    rc, out = run_with_audit(
        real, ("> | schemeId | announcement | gas |\n> |---|---|---|\n"
               f"> | **2** | 1 096 B | {gas3:,} |\n> | **3** | 1 129 B | {gas2:,} |\n")
        .replace(",", " "))
    case("a blockquoted table's swap is caught", rc, 1)
    rc, out = run_with_audit(
        real, ("> | schemeId | announcement | gas |\n> |---|---|---|\n"
               f"> | **2** | 1 096 B | {gas2:,} |\n> | **3** | 1 129 B | {gas3:,} |\n")
        .replace(",", " "))
    case("and rightly assigned it passes in that spelling too", rc, 0)
    # The committed specification's own shape: a first cell naming TWO schemes.
    gas6 = next(c["nonzero"]["total_gas"] for c in real["cases"]
                if c["name"] == "schemeId 6 announcement, category 2")
    mt_s = f"{memo_tot:,}".replace(",", " ")
    g6_s = f"{gas6:,}".replace(",", " ")
    rc, out = run_with_audit(
        real, ("| schemeId | memo | gas |\n|---|---|---|\n"
               f"| 4, 5 (memo) | 8 B | {mt_s} |\n"))
    case("a two-scheme first cell binds to both schemes' receipts", rc, 0)
    rc, out = run_with_audit(
        real, ("| schemeId | memo | gas |\n|---|---|---|\n"
               f"| 4, 5 (memo) | 8 B | {g6_s} |\n"))
    case("and does not borrow a third scheme's receipt", rc, 1)
    # GFM permits an ESCAPED pipe inside a cell; a parser counting raw pipes shifts
    # every later cell, moving the totals out of the gas column and out of the sweep.
    rc, out = run_with_audit(
        real, ("schemeId | note | gas\n---|---|---\n"
               f"**2** | harmless \\| note | {gas3:,}\n"
               f"**3** | harmless \\| note | {gas2:,}\n").replace(",", " "))
    case("an escaped pipe does not hide a swapped column", rc, 1)
    rc, out = run_with_audit(
        real, ("schemeId | note | gas\n---|---|---\n"
               f"**2** | harmless \\| note | {gas2:,}\n"
               f"**3** | harmless \\| note | {gas3:,}\n").replace(",", " "))
    case("and rightly assigned, the escaped-pipe table passes", rc, 0)
    # The escape can sit in the HEADER instead: raw splitting then shifts the header
    # cells while the figure's column index stays put, so the gas column reads as
    # some other column and the row leaves the sweep.
    rc, out = run_with_audit(
        real, ("schemeId | notes \\| aliases | gas\n---|---|---\n"
               f"**2** | plain note | {gas3:,}\n"
               f"**3** | plain note | {gas2:,}\n").replace(",", " "))
    case("an escaped pipe in the header does not shift the gas column", rc, 1)

    # The synthetic set proves the tool's logic. This proves the committed measurements actually
    # satisfy it -- a different claim, and the one a reader of §7 cares about. Skipped rather
    # than failed where the file is absent, because this suite also runs from temp trees
    # that have no `harness/`.
    committed = TOOL.parent.parent / "harness/announcement/measured.json"
    if committed.is_file():
        rc, out = run(json.loads(committed.read_text(encoding="utf-8")))
        case("the committed measurements pass", rc, 0)
        case("and every row of §6's table is among them", "nothing measured it" in out, False)
    else:
        case("SKIPPED -- no committed measurements in this tree", True, True)

    print("\nan epistemic marker classifies a figure, and its SCOPE is the paragraph")
    # The 22 untraced figures were closed by classification rather than by measurement, so the
    # marker's reach is now load-bearing. It was three lines, arbitrarily, and a marker placed
    # correctly at the head of a paragraph failed to reach a figure five lines down -- so a
    # figure that HAD been classified still reported as untraced.
    real_gas = real["cases"][1]["nonzero"]["total_gas"]
    bogus = real_gas + 11
    marked = (f"<!-- gas-external: somebody else's published figure -->\n"
              f"line one of the paragraph\nline two\nline three\nline four\n"
              f"and then **{bogus} gas** appears here.\n")
    rc, out = run_with_doc(real, marked)
    case("a marker reaches a figure five lines into its paragraph", rc, 0)

    # And it stops at the blank line. A marker that reached to the end of a section would let one
    # classification quietly cover figures nobody looked at.
    beyond = (f"<!-- gas-external: somebody else's published figure -->\n"
              f"the marked paragraph.\n\na different paragraph with **{bogus} gas** in it.\n")
    rc, out = run_with_doc(real, beyond)
    case("but not past the blank line into the next paragraph", rc, 1)

    # An unknown marker kind is not a marker. Otherwise `<!-- gas-whatever: -->` silences a
    # figure and reads like it classified one.
    unknown = (f"<!-- gas-probably-fine: trust me -->\n"
               f"a paragraph with **{bogus} gas** in it.\n")
    rc, out = run_with_doc(real, unknown)
    case("an unrecognised marker kind exempts nothing", rc, 1)

    print("\nusage")
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([sys.executable, str(TOOL), tmp], capture_output=True, text=True)
        case("a tree with no measurements exits 2", r.returncode, 2)

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: check_measured behaves as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
