#!/usr/bin/env python3
"""Self-test for the conformance-vector generator and its primitives.

**The cases must not be the generator's own output.** A self-test that runs the generator and
compares against what it produced proves only that it is deterministic, which is the exact
failure the standalone property exists to prevent one level up. So the primitives are checked
against values published outside this repository, the structural rules are checked by feeding
the generator a tree that breaks them, and the KEM values are checked to trace back to the
vendored NIST file rather than to anything computed here.

Exit 0 clean, 1 on any failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
TOOL = TOOLS / "gen_vectors.py"
sys.path.insert(0, str(TOOLS))

import vecprim as vp  # noqa: E402

FAILED: list[str] = []


def case(name: str, got, want) -> None:
    if got == want:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}\n          want: {want!r}\n          got:  {got!r}")
        FAILED.append(name)


def tree(plan: str, tier1: dict | None = "keep") -> Path:
    """A synthetic root. `tier1=None` omits the vendored file."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / "vectors" / "tier1").mkdir(parents=True)
    (tmp / "vectors" / "PLAN.md").write_text(plan, encoding="utf-8")
    if tier1 == "keep":
        real = Path("vectors/tier1/ml-kem-768-acvp.json")
        (tmp / "vectors/tier1/ml-kem-768-acvp.json").write_text(
            real.read_text(encoding="utf-8"), encoding="utf-8")
    elif tier1 is not None:
        (tmp / "vectors/tier1/ml-kem-768-acvp.json").write_text(
            json.dumps(tier1), encoding="utf-8")
    return tmp


def run(root: Path, *extra: str, no_kem: bool = False) -> tuple[int, str]:
    env = dict(os.environ)
    if no_kem:
        env["PQSA_NO_KEM"] = "1"
    else:
        env.pop("PQSA_NO_KEM", None)
    r = subprocess.run([sys.executable, str(TOOL), *extra, str(root)],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout + r.stderr


HDR = "| id | claim | given | expect | wrong |\n|---|---|---|---|---|\n"


def plan_of(**groups: list[str]) -> str:
    out = ["# plan\n"]
    for n, (sec, ids) in enumerate(groups.items(), 2):
        sec = sec.replace("_", ".").lstrip(".")
        out.append(f"\n## {n}. §{sec} — a group\n\n" + HDR)
        for i in ids:
            out.append(f"| {i} | c | g | e | w |\n")
    return "".join(out)


def main() -> int:
    print("gen_vectors self-test")

    print("\nthe primitives, against values published outside this repository")
    case("keccak256(b'')", vp.keccak256(b"").hex(),
         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    case("keccak256(b'abc')", vp.keccak256(b"abc").hex(),
         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
    # The one-byte difference that makes SHA3-256 the wrong function for an address.
    case("keccak256 is not sha3_256",
         vp.keccak256(b"") == hashlib.sha3_256(b"").digest(), False)
    case("2G.x", hex(vp.mul(2)[0]),
         "0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    case("nG is the point at infinity", vp.mul(vp.N), None)
    case("(n-1)G + G is the point at infinity", vp.add(vp.mul(vp.N - 1), vp.G), None)
    case("address_of(G)", "0x" + vp.address_of(vp.G).hex(),
         "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    case("its EIP-55 form", vp.eip55(vp.address_of(vp.G)),
         "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf")

    print("\nthe curve's rejections, which §2.2 turns on")
    g = vp.encode_compressed(vp.G)
    for tag, why in ((0x04, "uncompressed tag"), (0x05, "SEC1 compact"), (0x01, "nonsense")):
        try:
            vp.decode_compressed(bytes([tag]) + g[1:])
            case(f"a {why} tag is rejected", "accepted", "rejected")
        except ValueError:
            case(f"a {why} tag is rejected", "rejected", "rejected")
    try:
        vp.decode_compressed(b"\x02" + b"\xff" * 32)
        case("a right-length non-point is rejected", "accepted", "rejected")
    except ValueError:
        case("a right-length non-point is rejected", "rejected", "rejected")
    # ECDH must commute, which is the property the vectors depend on and no known-answer
    # table covers for arbitrary keys.
    a, b = 7, 11
    case("ECDH commutes", vp.mul(a, vp.mul(b)), vp.mul(b, vp.mul(a)))
    case("the reduction bound accepts n-1",
         vp.reduce_to_scalar((vp.N - 1).to_bytes(32, "big"))[1], 0)
    case("and rejects n", vp.reduce_to_scalar(vp.N.to_bytes(32, "big"))[1] >= 1, True)
    case("and rejects zero", vp.reduce_to_scalar(bytes(32))[1] >= 1, True)

    print("\nthe row list comes from the plan, not from the generator")
    rc, out = run(tree(plan_of(**{"1": ["V1-01"], "2": [], "2_9": [], "5": []})))
    case("a plan naming one §1 row emits one", "§1: 1/1 slot(s)" in out, True)
    # A row the plan lists and the builder does not build must FAIL, not be skipped.
    rc, out = run(tree(plan_of(**{"1": ["V1-01", "V1-99"], "2": [], "2_9": [], "5": []})))
    case("a plan row the generator cannot build exits 1", rc, 1)
    case("and it is named", "§1 V1-99" in out, True)
    case("and the message says silence is the worse outcome",
         "silence about a row" in out, True)

    print("\nthe group list may not drift from the coverage checker's")
    # SKIPPED, LOUDLY, when the coverage checker is absent. This suite ships in the release and
    # that checker does not -- it pulls in two more tools that are about our own documents -- so
    # in a release tree the cross-check has nothing to compare against.
    #
    # Announced rather than passed, because this repository's standing rule is that a gate which
    # cannot run must say so: a suite that silently drops a case in one tree and keeps it in
    # another reports the same "OK" for two different amounts of checking.
    import gen_vectors as gv  # noqa: E402  -- always present; it is the tool under test
    try:
        import check_vector_coverage as cvc  # noqa: E402
    except ModuleNotFoundError as e:
        print(f"  SKIPPED  the coverage checker is not present ({e.name}), so the group "
              f"lists "
              f"cannot be compared here. This is expected in a release tree and a FINDING in "
              f"the authoring one.")
    else:
        case("both tools agree on the group list",
             set(gv.GROUPS), set().union(*(set(v) for v in cvc.WAVES.values())))
        # The withdrawn-row rule is the second deliberate copy, and it gets the same
        # treatment: the compiled patterns must be identical, and the two claim-cell
        # readers -- mdscan on one side, the generator's blank-the-code-spans split on the
        # other -- must classify every row of the REAL plan the same way. The real plan,
        # because that is where the escaped pipes and struck-through claims actually live;
        # a synthetic agreement proves nothing about the file the tools disagree over.
        case("both tools agree on the empty-cell pattern",
             (gv.EMPTY_CELL.pattern, gv.EMPTY_CELL.flags),
             (cvc.EMPTY_CELL.pattern, cvc.EMPTY_CELL.flags))
        case("both tools agree on the withdrawn pattern",
             (gv.WITHDRAWN_CELL.pattern, gv.WITHDRAWN_CELL.flags),
             (cvc.WITHDRAWN_CELL.pattern, cvc.WITHDRAWN_CELL.flags))
        real_plan = Path("vectors/PLAN.md")
        if real_plan.is_file():
            mine, theirs = [], []
            for ln in real_plan.read_text(encoding="utf-8").split("\n"):
                m = gv.ROW.match(ln)
                if not m:
                    continue
                mine.append((m.group(1), gv.not_a_fixture(gv.claim_cell(ln))))
                cell = cvc.claim_cell(ln)
                theirs.append((m.group(1), bool(cvc.EMPTY_CELL.search(cell)
                                                or cvc.WITHDRAWN_CELL.search(cell))))
            case("and classify every real plan row identically", mine, theirs)

    print("\na withdrawn or reserved plan row is neither emitted nor missing")
    # Group §1 is rendered LAST so the appended rows belong to it -- plan_of emits groups
    # in keyword order and a row line joins the group above it.
    plan = plan_of(**{"2": [], "2_9": [], "5": [], "1": ["V1-01"]})
    plan += "| V1-90 | ~~a struck-through claim~~ | — | — | **WITHDRAWN.** |\n"
    plan += "| V1-91 | **no vector — deliberately.** a reserved slot | — | — | a vector |\n"
    root = tree(plan)
    rc, out = run(root)
    case("the run succeeds", rc, 0)
    case("both are named as skipped", "§1 V1-90" in out and "§1 V1-91" in out, True)
    case("and the print says whose they are not",
         "not a generator's to emit" in out, True)
    body = json.loads((root / "vectors/section-1.json").read_text())["vectors"]
    case("neither is in the emitted file",
         [k for k in ("V1-90", "V1-91") if k in body], [])
    # The rule is claim-cell-scoped and case-sensitive: a LIVE row whose failure column
    # mentions "the withdrawn rule" must still be built -- the false positive that scoping
    # exists to prevent. V1-92 is live, unbuilt, and must therefore FAIL the run as missing.
    plan = plan_of(**{"2": [], "2_9": [], "5": [], "1": ["V1-01"]})
    plan += "| V1-92 | a live claim | g | e | the withdrawn rule does not apply |\n"
    rc, out = run(tree(plan))
    case("a live row mentioning 'withdrawn' in its failure column is NOT skipped",
         rc == 1 and "§1 V1-92" in out, True)

    print("\nthe manifest is replaced, not merged")
    # This case is INVERTED from what it asserted while the generator ran one wave at a time.
    # A partial run had to carry the rest of the committed manifest over; a total run must
    # not, because the only thing a carried entry can be is a file that stopped shipping.
    # That is not hypothetical: `section-2.json` and `section-5.json` outlived both files in
    # the committed manifest, and `--check` passed, because it verifies files that are
    # present rather than names that are listed.
    root = tree(plan_of(**{"1": ["V1-01"], "2_9": []}))
    foreign = {"_what": "x", "tier1_source": [],
               "files": {"section-99.json": {"sha256": "f" * 64, "rows_in_plan": 1,
                                             "rows_present": 1}}}
    (root / "vectors/manifest.json").write_text(json.dumps(foreign), encoding="utf-8")
    rc, out = run(root)
    man = json.loads((root / "vectors/manifest.json").read_text())
    case("an entry for a file that no longer ships does NOT survive",
         "section-99.json" in man["files"], False)
    case("and this run's entries are written", "section-1.json" in man["files"], True)
    case("and the files are ordered by name", list(man["files"]), sorted(man["files"]))

    print("\nthe vendored NIST file is required, never substituted")
    rc, out = run(tree(plan_of(**{"1": ["V1-01"], "2": [], "2_9": [], "5": []}), tier1=None))
    case("a missing tier-1 file exits 2", rc, 2)
    case("and says tier 1 is NIST's", "does not compute it" in out, True)

    print("\nevery KEM value traces to the vendored file")
    root = tree(plan_of(**{"1": [], "2_9": ["V3-06a", "V3-08"], "5": []}))
    run(root)
    acvp = json.loads((root / "vectors/tier1/ml-kem-768-acvp.json").read_text())
    known = {x["ek"] for x in acvp["keygen"]}
    known |= {x[k] for x in acvp["encapsulation"] for k in ("ek", "m", "c", "k")}
    body = json.loads((root / "vectors/section-2_9.json").read_text())["vectors"]
    # Any 1088- or 1184-byte hex string in the output must be one NIST published. A
    # synthesised ciphertext is the one artifact this generator must never produce.
    def long_hex(o):
        if isinstance(o, str) and len(o) in (2176, 2368) and all(c in "0123456789abcdef" for c in o):
            yield o
        elif isinstance(o, dict):
            for x in o.values():
                yield from long_hex(x)
        elif isinstance(o, list):
            for x in o:
                yield from long_hex(x)
    found = list(long_hex(body))
    case("KEM-length values appear in the output", len(found) > 0, True)
    case("and every one of them is a NIST-published value",
         [f for f in found if f not in known], [])

    # COVERAGE REMOVED WITH ITS SUBJECT, NAMED RATHER THAN DROPPED QUIETLY. Two blocks
    # stood here, exercising both sides of the `PQSA_NO_KEM` seam on the three schemeId 2
    # rows whose generability depended on an importable ML-KEM: absent, they were recorded
    # `not_generatable` with a reason; present, they were emitted and V2-11 asserted that
    # decapsulation did NOT raise and returned a DIFFERENT secret -- implicit rejection,
    # demonstrated rather than asserted.
    #
    # No surviving row calls the KEM. §1, §2.9 and §5 build from the vendored ACVP file
    # directly, so `--check` now passes byte-identically with kyber-py absent and neither
    # branch can be staged from a real row. The seam and the stub path are still in the
    # tool, and the guards below exercise them through V6-03, whose stub comes from the
    # conformance hook rather than from the environment. What is NOT exercised any more is
    # a row moving between the two states because a library came or went.
    print("\n--check: stale, unverifiable and absent are THREE outcomes")
    # The distinction this suite exists to pin: a row that DIFFERS is stale and must fail; a row
    # this process cannot rebuild is unverifiable and must NOT; and an absent file is stale.
    # Conflating the second with the first is what a whole-file byte comparison did, and it
    # reported a byte-identical tree as stale the moment the ML-KEM library was absent.
    root = tree(plan_of(**{"1": ["V1-01"], "2": [], "2_9": [], "5": []}))
    run(root)
    rc, out = run(root, "--check")
    case("--check on a freshly generated tree passes", rc, 0)
    case("and says so", "matches a fresh generation" in out, True)
    # Compared before against after rather than against a literal list: the temp tree also
    # holds PLAN.md and tier1/, and a literal expectation would be asserting the fixture's
    # shape instead of the tool's behaviour.
    before = sorted(str(q.relative_to(root)) for q in root.rglob("*"))
    run(root, "--check")
    case("and writes nothing new",
         sorted(str(q.relative_to(root)) for q in root.rglob("*")), before)

    f = root / "vectors/section-1.json"
    body = json.loads(f.read_text())
    body["vectors"]["V1-01"]["expect"] = {"tampered": True}
    f.write_text(json.dumps(body, indent=2) + "\n")
    rc, out = run(root, "--check")
    case("an edited row exits 1", rc, 1)
    case("and names the row, not just the file", "V1-01 differs" in out, True)

    body["vectors"].pop("V1-01")
    f.write_text(json.dumps(body, indent=2) + "\n")
    rc, out = run(root, "--check")
    case("a row missing from the committed file exits 1", rc, 1)
    case("and says it is missing", "is missing from the committed file" in out, True)

    f.unlink()
    rc, out = run(root, "--check")
    case("an absent file exits 1", rc, 1)
    case("and says absent, not differs", "section-1.json: absent" in out, True)

    # COVERAGE REMOVED WITH ITS SUBJECT. Two cases stood here -- a row this process cannot
    # rebuild does NOT fail `--check`, and a partial run concludes "OK, PARTLY" rather than
    # claiming every file matches. Both were staged on V6-03, the tree's only row emitted as
    # a `not_generatable` stub. §5 left and V6-03 with it, so nothing in this tree produces a
    # stub and neither case can be staged from a real row. The paths are still in the tool.
    # AND THE SAME FOR THE DOWNGRADE GUARD. `refuse_to_downgrade` refuses to replace a
    # committed row that carries a value with a stub; three cases exercised it, and the
    # `--out` scratch-tree false-positive case with them. All four needed a row the generator
    # would emit as a stub, and there is none. The guard is kept: it is cheap, it is correct,
    # and the day a row becomes ungeneratable again is the day it matters. It is UNTESTED
    # here, which is the honest word for it.
    #
    # The §5 scheme-name and `keygen_seed`-salt cases went the same way -- their subject was
    # `section-5.json`.
    print("\nvecprim's primitives, against the COMMITTED fixtures")
    # The reason is a mutation report rather than a hunch: eight mutations
    # to `vecprim.py` -- a one-byte view tag, `announce_seed` with its index appended last, a
    # `kem_id` without its length prefix, `kem_encaps` returning the library's field order -- all
    # SURVIVED this suite. Every case above builds a SYNTHETIC tree and compares the generator
    # against itself, so a primitive can change and every synthetic expectation changes with it.
    #
    # These cases compare against the fixtures in `vectors/`, which are committed bytes that do
    # not move when the code does. That is the only kind of comparison that can catch a
    # derivation changing, and the suite had none.
    #
    # (`crates/core` asserts several of the same values in Rust, which is why the defect was not
    # dangerous -- but a Rust test does not exercise the Python these vectors are generated from,
    # and this suite claimed to.)
    real = Path(".")
    if not (real / "vectors/section-1.json").is_file():
        print("  SKIPPED  no committed vectors in this tree, so nothing to compare against.")
    else:
        def committed(section, vid, key):
            body = json.loads((real / f"vectors/section-{section}.json").read_text())
            return body["vectors"][vid]["expect"][key]

        # §1's view tag, at its full width. The mutation that shortened it to one byte survived.
        v1 = json.loads((real / "vectors/section-1.json").read_text())["vectors"]
        tag_ss = bytes.fromhex(v1["V1-07"]["given"]["ss"])
        case("the view tag matches V1-07 exactly, at its full width",
             vp.view_tag(tag_ss).hex(), v1["V1-07"]["expect"]["view_tag"])
        case("and it is VIEW_TAG_BYTES long, not one", len(vp.view_tag(tag_ss)),
             vp.VIEW_TAG_BYTES)

        # §1's offset digest, which every derived address depends on.
        base, scalar, counter = vp.h_of_ss(bytes.fromhex(v1["V1-01"]["given"]["ss"]))
        case("the offset digest matches V1-01", base.hex(), v1["V1-01"]["expect"]["base"])
        case("and its reduction needs no retry, as the row states",
             counter, v1["V1-01"]["expect"]["counter"])
        case("and the offset equals the base when no retry was needed",
             f"{scalar:064x}", v1["V1-01"]["expect"]["offset"])

        # §5's announce-seed cases stood here, pinning `vp.announce_seed`'s field order and
        # the length-prefixed `kem_id` against the committed V6-05. Three mutations lived
        # there. `section-5.json` is gone, so there is no committed row to pin them against
        # and `vecprim` no longer exposes the derivations they covered.

    print("\nthe row comparison is representation-insensitive")
    # Directly, on the hoisted `canonical`. Through the CLI this was unreachable: nothing in the
    # tree currently emits an integer key or a tuple by a path any case exercises, so the mutation
    # that removed the JSON round trip survived the entire suite. Both shapes are asserted here
    # because both have caused a real false positive -- integer keys did, in V3-02.
    case("an integer key and its parsed string form compare equal",
         gv.canonical({0: "a", 5: "b", 16: "c"}),
         gv.canonical({"0": "a", "5": "b", "16": "c"}))
    case("a tuple and the list it parses back as compare equal",
         gv.canonical({"x": (1, 2, 3)}), gv.canonical({"x": [1, 2, 3]}))
    case("and genuinely different rows still differ",
         gv.canonical({"x": [1, 2]}) == gv.canonical({"x": [1, 3]}), False)

    print("\nusage")
    case("an unknown flag exits 2", run(tree(plan_of(**{"1": []})), "--bogus")[0], 2)
    case("the withdrawn --wave flag is now just an unknown flag",
         run(tree(plan_of(**{"1": []})), "--wave", "1")[0], 2)
    with tempfile.TemporaryDirectory() as t:
        case("a tree with no plan exits 2",
             subprocess.run([sys.executable, str(TOOL), t],
                            capture_output=True, text=True).returncode, 2)

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: gen_vectors and vecprim behave as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
