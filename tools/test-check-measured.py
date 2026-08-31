#!/usr/bin/env python3
"""Self-test for the offline gas-snapshot and documentation linter."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "check_measured.py"
FAILED: list[str] = []

# Synthetic snapshots: temp trees have no repo measurements, and the cases
# must not depend on live gas figures.


def synthetic() -> dict:
    """A minimal announcement snapshot with upper-bound and real-sample cases."""
    sys.path.insert(0, str(TOOL.parent))
    import derive_sizes

    cases = []
    diagnostics = []
    stealth_address = "0x6dbb67f21b650304b5f459833188f52db07c2b43"

    def row(name: str, scheme_id: int, kind: str, epk: int, md: int) -> None:
        payload = epk + md
        # Exact ABI shape and byte distribution for the benchmark fixture.
        calldata = 4 + 32 * 4 + 32 * ((epk + 31) // 32 + 1) + 32 * ((md + 31) // 32 + 1)
        epk_offset = 4 * 32
        md_offset = epk_offset + 32 + 32 * ((epk + 31) // 32)
        words = (scheme_id, int(stealth_address, 16), epk_offset, md_offset, epk, md)
        header_nonzero = 4 + sum(
            byte != 0 for value in words for byte in value.to_bytes(32, "big")
        )
        primary_zero = calldata - header_nonzero - payload
        primary_tokens = primary_zero + 4 * (calldata - primary_zero)
        probe_zero = calldata - header_nonzero
        probe_tokens = probe_zero + 4 * (calldata - probe_zero)
        execution = 5000 + 8 * calldata
        cases.append({
            "name": name,
            "scheme_id": scheme_id,
            "kind": kind,
            "epk_bytes": epk,
            "metadata_bytes": md,
            "transaction": {
                "calldata_bytes": calldata,
                "zero_bytes": primary_zero,
                "gas_used": max(
                    21_000 + 4 * primary_tokens + execution,
                    21_000 + 10 * primary_tokens,
                ),
            },
        })
        diagnostics.append({
            "name": f"{name}_execution_probe",
            "for_case": name,
            "kind": "zero_dynamic_fields_probe",
            "transaction": {
                "calldata_bytes": calldata,
                "zero_bytes": probe_zero,
                "gas_used": 21_000 + 4 * probe_tokens + execution,
            },
        })

    row("classical_upper_bound", 1, "dynamic_fields_upper_bound", 33, 1)
    epk, md = derive_sizes.SHAPES["schemeId 3 announcement"]
    row("scheme3_upper_bound", 3, "dynamic_fields_upper_bound", epk, md)
    row("scheme3_real_sample", 3, "real_sample", epk, md)
    return {
        "schema_version": 1,
        "benchmark": "announcement",
        "environment": {
            "hardfork": "prague",
            "contract_address": "0x55649E01B5Df198D18D95b5cc5051630cfD45564",
            "contract_code_sha256": "97b1a2b6e83d4d2d1184c28bfafe24df2463fcaec94e655b2b56ba5fc52a1b17",
        },
        "fixture": {"name": "scheme3-demo-v1", "sha256": "0" * 64},
        "results": cases,
        "diagnostics": diagnostics,
    }


def supporting_artifacts(
    root: Path,
    fixture_sha256: str,
    mutate: Callable[[dict, dict], None] | None = None,
) -> None:
    """Write the registration and payment snapshots a temp tree needs."""
    registration = {
        "schema_version": 1,
        "benchmark": "registration",
        "environment": {
            "hardfork": "prague",
            "contract_address": "0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538",
            "contract_code_sha256": "aacd1016938b107361de63f20c358350de9f78fa6033b7727853f0229c94b82f",
        },
        "fixture": {"name": "scheme3-demo-v1", "sha256": fixture_sha256},
        "results": [
            {
                "name": "classical_upper_bound",
                "scheme_id": 1,
                "kind": "dynamic_field_upper_bound",
                "meta_address_bytes": 66,
                "transaction": {
                    "calldata_bytes": 196,
                    "zero_bytes": 123,
                    "gas_used": 115_310,
                },
            },
            {
                "name": "scheme3_upper_bound",
                "scheme_id": 3,
                "kind": "dynamic_field_upper_bound",
                "meta_address_bytes": 1250,
                "transaction": {
                    "calldata_bytes": 1380,
                    "zero_bytes": 122,
                    "gas_used": 964_809,
                },
            },
            {
                "name": "scheme3_real_sample",
                "scheme_id": 3,
                "kind": "real_sample",
                "meta_address_bytes": 1250,
                "transaction": {
                    "calldata_bytes": 1380,
                    "zero_bytes": 128,
                    "gas_used": 964_737,
                },
            },
        ],
    }
    payment = {
        "schema_version": 1,
        "benchmark": "payment",
        "environment": {
            "hardfork": "prague",
            "announcer_address": "0x55649E01B5Df198D18D95b5cc5051630cfD45564",
            "announcer_code_sha256": "97b1a2b6e83d4d2d1184c28bfafe24df2463fcaec94e655b2b56ba5fc52a1b17",
        },
        "fixture": {
            "name": "scheme3-demo-v1",
            "sha256": fixture_sha256,
        },
        "results": [
            {
                "name": "scheme3_real_sample",
                "scheme_id": 3,
                "kind": "real_sample",
                "transactions": {
                    "announce": {
                        "calldata_bytes": 1380,
                        "zero_bytes": 230,
                        "gas_used": 69_300,
                    },
                    "fund": {"gas_used": 21_000},
                    "spend": {"gas_used": 21_000},
                },
            }
        ],
    }
    if mutate is not None:
        mutate(registration, payment)
    for directory, body in (("registration", registration), ("payment", payment)):
        path = root / "harness" / directory
        path.mkdir(parents=True, exist_ok=True)
        (path / "measured.json").write_text(json.dumps(body), encoding="utf-8")


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
        supporting_artifacts(root, data["fixture"]["sha256"])
        (root / "AUDIT.md").write_text(text, encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(TOOL), str(root)], capture_output=True, text=True
        )
        return r.returncode, r.stdout + r.stderr


def run_with_doc(data: dict, doc_text: str, name: str = "scheme-3.md") -> tuple[int, str]:
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
        supporting_artifacts(root, data["fixture"]["sha256"])
        (root / "docs").mkdir()
        (root / "docs" / name).write_text(doc_text, encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(TOOL), str(root)], capture_output=True, text=True
        )
        return r.returncode, r.stdout + r.stderr


def run(
    data: dict,
    supporting_mutation: Callable[[dict, dict], None] | None = None,
) -> tuple[int, str]:
    """Run the tool against a tree holding `data` as the measurements.

    The real `tools/` is symlinked in, because the tool imports `derive_sizes` from beside
    itself -- so a temp tree needs the real one to compare the specification's lengths against.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(data), encoding="utf-8"
        )
        supporting_artifacts(
            root,
            data["fixture"]["sha256"],
            supporting_mutation,
        )
        r = subprocess.run(
            [sys.executable, str(TOOL), str(root)], capture_output=True, text=True
        )
        return r.returncode, r.stdout + r.stderr


def main() -> int:
    print("check_measured self-test")
    real = synthetic()

    print("\na complete snapshot set")
    rc, out = run(real)
    case("a complete snapshot set passes", rc, 0)
    case("and identifies the live correctness gate",
         "harness/bench.py all --check" in out, True)

    print("\nschema identity is explicit")
    d = copy.deepcopy(real)
    d["schema_version"] = 0
    rc, out = run(d)
    case("a wrong schema_version exits 1", rc, 1)
    case("and says schema_version is wrong", "schema_version" in out, True)

    print("\ncanonical execution environment is explicit")
    d = copy.deepcopy(real)
    d["environment"]["contract_code_sha256"] = "0" * 64
    rc, out = run(d)
    case("a different announcer runtime exits 1", rc, 1)
    case("and names the benchmark environment", "wrong benchmark environment" in out, True)

    print("\nall benchmarks share the same real fixture")
    def change_registration_fixture(registration: dict, _payment: dict) -> None:
        registration["fixture"]["sha256"] = "1" * 64

    rc, out = run(real, change_registration_fixture)
    case("a mismatched fixture exits 1", rc, 1)
    case("and names the shared-fixture violation",
         "do not share one real fixture" in out, True)

    print("\nresults cannot be empty")
    d = copy.deepcopy(real)
    d["results"] = []
    rc, out = run(d)
    case("an empty result set exits 1", rc, 1)
    case("and says results is empty", "results is empty or invalid" in out, True)

    print("\nsupporting snapshots have the same identity checks")

    def change_registration_environment(registration: dict, _payment: dict) -> None:
        registration["environment"]["hardfork"] = "cancun"

    rc, out = run(real, change_registration_environment)
    case("a wrong registration environment exits 1", rc, 1)
    case("and names the registration artifact",
         "harness/registration/measured.json" in out, True)

    def remove_payment_fixture(_registration: dict, payment: dict) -> None:
        del payment["fixture"]["sha256"]

    rc, out = run(real, remove_payment_fixture)
    case("a payment without fixture identity exits 1", rc, 1)
    case("and names the missing fixture", "missing real fixture identity" in out, True)

    print("\nthe prose sweep over docs/")
    real_gas = real["results"][1]["transaction"]["gas_used"]
    rc, out = run_with_doc(real, f"costs **{real_gas} gas** per announcement.\n")
    case("a figure that IS a receipt passes", rc, 0)
    case("and it is counted", "gas figures quoted in prose" in out, True)

    rc, out = run_with_doc(real, f"costs **{real_gas + 7} gas** per announcement.\n")
    case("a figure that is NOT a receipt exits 1", rc, 1)
    case("and names the missing snapshot", "not in measured.json" in out, True)

    # The reason the sweep over the docs directory does not key on the word `gas`: the SECOND
    # operand of a
    # comparison sits outside any keyword window, and a comparison is where a stale figure
    # hides, since a reader checks the ratio and not the operands.
    other = real["results"][0]["transaction"]["gas_used"]
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
    transcript = "transcripts-scheme-3.md"
    # The exemption's scope is a GENERATED SPAN: an `output-of` marker's fenced body. The
    # tail line is legitimate there and only there.
    tail = "watch record 53 B 03f6b94c…00000000000000000000000200000014"
    in_span = f"# t\n\n<!-- output-of: demo-3 -->\n```text\n{tail}\n```\n"
    rc, out = run_with_doc(real, in_span, transcript)
    case("an elided hex tail INSIDE a generated span is not treated as gas", rc, 0)
    rc, out = run_with_doc(real, f"# t\n\nhand-written: {tail}\n", transcript)
    case("the SAME line in the transcript's hand-written prose IS", rc, 1)
    rc, out = run_with_doc(real, in_span)
    case("and a generated-looking span in an ordinary doc exempts nothing", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-3 -->\n```text\nthe run cost 00000000000000000000000200000014 exactly.\n```\n",
        transcript,
    )
    case("and the same digits without the elision are caught, even inside a span", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-3 -->\n```text\nthe estimated execution cost is …99999 gas.\n```\n",
        transcript,
    )
    case("and a bare-ellipsis figure is too", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-3 -->\n```text\nsums to 01f6b94c…99 999 in that configuration.\n```\n",
        transcript,
    )
    case("and a SPACED figure behind a hex ellipsis is too — hex tails have no spaces", rc, 1)
    rc, out = run_with_doc(
        real,
        "<!-- output-of: demo-3 -->\n```text\nthe preface…99999 gas was the estimate.\n```\n",
        transcript,
    )
    case("and a WORD ending in hex letters exempts nothing even there", rc, 1)
    rc, out = run_with_doc(real, "the deadbee7…99999 gas estimate held.\n")
    case("and a hex-shaped WORD in ordinary prose is caught by the scope", rc, 1)

    print("\na multi-scheme receipt vouches for every scheme it names")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "harness/announcement").mkdir(parents=True)
        (root / "harness/announcement/measured.json").write_text(
            json.dumps(real), encoding="utf-8")
        supporting_artifacts(root, real["fixture"]["sha256"])
        (root / "harness/shared").mkdir(parents=True)
        (root / "harness/shared/measured.json").write_text(json.dumps({
            "schema_version": 1,
            "benchmark": "shared",
            "results": [{"name": "memo (schemeIds 1, 3)",
                         "gas_used": 177_810}],
        }), encoding="utf-8")
        (root / "docs").mkdir()
        (root / "docs" / "memo.md").write_text(
            "schemeIds 1 and 3 share a memo path costing **177 810 gas**.\n",
            encoding="utf-8")
        r = subprocess.run([sys.executable, str(TOOL), str(root)],
                           capture_output=True, text=True)
        case("the shared receipt vouches for both schemes", r.returncode, 0)
        (root / "docs" / "memo.md").write_text(
            "schemeIds 1 and 3 share a memo path costing **177 811 gas**.\n",
            encoding="utf-8")
        r = subprocess.run([sys.executable, str(TOOL), str(root)],
                           capture_output=True, text=True)
        case("an off-by-one shared figure remains unfalsifiable", r.returncode, 1)

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
    # An INLINE marker — one the anchored grammar never recognises, so its
    # fenced block is never re-run — must confer no exemption: the two parsers sharing one
    # grammar is what makes "generated span" mean "authenticated span".
    rc, out = run_with_doc(
        real,
        f"prefix <!-- output-of: demo-3 -->\n```text\n{tail}\n```\n",
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

    # A DERIVED figure: prose comparing two schemes quotes their difference. The prose
    # names the schemes the numbers actually come from (cases[1] is schemeId 3,
    # cases[0] the classical baseline) — a delta attributed to schemes it was not
    # computed from is exactly what the scheme-binding check rejects.
    delta = real_gas - other
    rc, out = run_with_doc(real, f"schemeId 3 costs {delta} more gas than classical.\n")
    case("a difference between two receipts is allowed", rc, 0)
    rc, out = run_with_doc(real, f"schemeId 3 costs {delta + 1} more gas than classical.\n")
    case("but a wrong difference is not", rc, 1)
    # THE BINDING ITSELF, on the reviewer's exact shape: swap two schemes' totals in
    # prose — both numbers are receipts, both claims false, and set membership alone
    # certified them.
    gas1 = real["results"][0]["transaction"]["gas_used"]   # classical
    gas3 = real["results"][1]["transaction"]["gas_used"]   # schemeId 3
    rc, out = run_with_doc(
        real, f"schemeId 1 costs {gas3:,} gas.\n\nschemeId 3 costs {gas1:,} gas.\n"
              .replace(",", " "))
    case("swapped scheme totals are misassigned receipts, not a pass", rc, 1)
    case("and the finding names the misassignment",
         "assigned to the wrong claim" in out, True)
    rc, out = run_with_doc(
        real, f"schemeId 1 costs {gas1:,} gas.\n\nschemeId 3 costs {gas3:,} gas.\n"
              .replace(",", " "))
    case("the same totals rightly assigned pass", rc, 0)
    # ONE paragraph naming both schemes, totals swapped: under a scope-wide union each
    # figure stays vouched by the OTHER claim's receipt. The binding is to the nearest
    # preceding mention — the claim the figure actually belongs to.
    rc, out = run_with_doc(
        real, f"schemeId 1 costs {gas3:,} gas where schemeId 3 costs {gas1:,} gas.\n"
              .replace(",", " "))
    case("a swap inside one sentence is caught, not vouched by the union", rc, 1)
    rc, out = run_with_doc(
        real, f"schemeId 1 costs {gas1:,} gas where schemeId 3 costs {gas3:,} gas.\n"
              .replace(",", " "))
    case("and the same sentence rightly assigned passes", rc, 0)

    print("\na table's gas column is a gas claim, and its row names its scheme")
    # The reviewer's counterexample verbatim in shape: a README-style ladder table, no
    # scheme named in prose, the unit named only by the column HEADER, totals swapped.
    def ladder(a: int, b: int) -> str:
        return ("## The ladder\n\n"
                "| schemeId | announcement | gas | state |\n"
                "|---|---|---|---|\n"
                f"| **1** | 34 B | {a:,} | none |\n"
                f"| **3** | 1 122 B | {b:,} | none |\n").replace(",", " ")
    rc, out = run_with_audit(real, ladder(gas1, gas3))
    case("a rightly assigned ladder table passes", rc, 0)
    rc, out = run_with_audit(real, ladder(gas3, gas1))
    case("the README two-row swap is caught", rc, 1)
    case("and both rows are named",
         out.count("assigned to the wrong claim"), 2)
    # A row may only borrow receipts from the scheme it names.
    rc, out = run_with_audit(
        real, ("| schemeId | announcement | gas |\n|---|---|---|\n"
               f"| **1** | 34 B | {gas3:,} |\n").replace(",", " "))
    case("a scheme's row does not borrow another scheme's receipt", rc, 1)
    case("and says the figure is not that scheme's",
         "assigned to the wrong claim" in out, True)

    print("\na table is a table in every GFM spelling, and a first cell may name two schemes")
    # GFM permits tables without leading/trailing pipes and inside blockquotes; a
    # swap must be caught in each spelling, not only the fully piped one.
    rc, out = run_with_audit(
        real, ("schemeId | announcement | gas\n---|---|---\n"
               f"**1** | 34 B | {gas3:,}\n**3** | 1 122 B | {gas1:,}\n")
        .replace(",", " "))
    case("a no-leading-pipe table's swap is caught", rc, 1)
    rc, out = run_with_audit(
        real, ("> | schemeId | announcement | gas |\n> |---|---|---|\n"
               f"> | **1** | 34 B | {gas3:,} |\n> | **3** | 1 122 B | {gas1:,} |\n")
        .replace(",", " "))
    case("a blockquoted table's swap is caught", rc, 1)
    rc, out = run_with_audit(
        real, ("> | schemeId | announcement | gas |\n> |---|---|---|\n"
               f"> | **1** | 34 B | {gas1:,} |\n> | **3** | 1 122 B | {gas3:,} |\n")
        .replace(",", " "))
    case("and rightly assigned it passes in that spelling too", rc, 0)
    # GFM permits an ESCAPED pipe inside a cell; a parser counting raw pipes shifts
    # every later cell, moving the totals out of the gas column and out of the sweep.
    rc, out = run_with_audit(
        real, ("schemeId | note | gas\n---|---|---\n"
               f"**1** | harmless \\| note | {gas3:,}\n"
               f"**3** | harmless \\| note | {gas1:,}\n").replace(",", " "))
    case("an escaped pipe does not hide a swapped column", rc, 1)
    rc, out = run_with_audit(
        real, ("schemeId | note | gas\n---|---|---\n"
               f"**1** | harmless \\| note | {gas1:,}\n"
               f"**3** | harmless \\| note | {gas3:,}\n").replace(",", " "))
    case("and rightly assigned, the escaped-pipe table passes", rc, 0)
    # The escape can sit in the HEADER instead: raw splitting then shifts the header
    # cells while the figure's column index stays put, so the gas column reads as
    # some other column and the row leaves the sweep.
    rc, out = run_with_audit(
        real, ("schemeId | notes \\| aliases | gas\n---|---|---\n"
               f"**1** | plain note | {gas3:,}\n"
               f"**3** | plain note | {gas1:,}\n").replace(",", " "))
    case("an escaped pipe in the header does not shift the gas column", rc, 1)

    print("\nthe committed tree, not a reduced temp fixture")
    committed = TOOL.parent.parent / "harness/announcement/measured.json"
    case("the committed announcement snapshot exists", committed.is_file(), True)
    if committed.is_file():
        rc, out = run(json.loads(committed.read_text(encoding="utf-8")))
        case("the committed announcement snapshot lints in isolation", rc, 0)
        case("and every row of §4's table is among them", "nothing measured it" in out, False)

    # The claim the name used to make: glob README, spec, and the other harness
    # receipts. That is `check_measured.py` on the real repository root.
    repo = TOOL.parent.parent
    r = subprocess.run(
        [sys.executable, str(TOOL), str(repo)], capture_output=True, text=True
    )
    case("the committed tree passes snapshot and prose lint",
         r.returncode, 0)

    print("\nan epistemic marker classifies a figure, and its SCOPE is the paragraph")
    # The 22 untraced figures were closed by classification rather than by measurement, so the
    # marker's reach is now load-bearing. It was three lines, arbitrarily, and a marker placed
    # correctly at the head of a paragraph failed to reach a figure five lines down -- so a
    # figure that HAD been classified still reported as untraced.
    real_gas = real["results"][1]["transaction"]["gas_used"]
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
    print("OK: check_measured matches the committed tree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
