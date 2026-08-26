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

    print("\nthe wave map may not drift from the coverage checker's")
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
        print(f"  SKIPPED  the coverage checker is not present ({e.name}), so the wave maps "
              f"cannot be compared here. This is expected in a release tree and a FINDING in "
              f"the authoring one.")
    else:
        case("both tools agree on wave 1's groups",
             set(gv.WAVES[1]), set(cvc.WAVES["1"]))
        case("both tools agree on wave 2's groups",
             set(gv.WAVES[2]), set(cvc.WAVES["2"]))
        case("both tools agree on wave 3's groups",
             set(gv.WAVES[3]), set(cvc.WAVES["3"]))
        case("neither tool has a wave the other lacks",
             set(str(w) for w in gv.WAVES), set(cvc.WAVES))
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

    print("\nthe manifest is merged across waves, not replaced")
    root = tree(plan_of(**{"1": ["V1-01"], "2": [], "2_9": [], "5": []}))
    foreign = {"_what": "x", "tier1_source": [],
               "files": {"section-99.json": {"sha256": "f" * 64, "rows_in_plan": 1,
                                             "rows_present": 1}}}
    (root / "vectors/manifest.json").write_text(json.dumps(foreign), encoding="utf-8")
    rc, out = run(root)
    man = json.loads((root / "vectors/manifest.json").read_text())
    case("another wave's entry survives a regeneration",
         "section-99.json" in man["files"], True)
    case("and this wave's entries are written beside it",
         "section-1.json" in man["files"], True)
    case("and the files are ordered by name, not by which wave ran last",
         list(man["files"]), sorted(man["files"]))

    print("\nthe vendored NIST file is required, never substituted")
    rc, out = run(tree(plan_of(**{"1": ["V1-01"], "2": [], "2_9": [], "5": []}), tier1=None))
    case("a missing tier-1 file exits 2", rc, 2)
    case("and says tier 1 is NIST's", "does not compute it" in out, True)

    print("\nevery KEM value traces to the vendored file")
    root = tree(plan_of(**{"1": [], "2": ["V2-05", "V2-10"], "2_9": [], "5": []}))
    run(root)
    acvp = json.loads((root / "vectors/tier1/ml-kem-768-acvp.json").read_text())
    known = {x["ek"] for x in acvp["keygen"]}
    known |= {x[k] for x in acvp["encapsulation"] for k in ("ek", "m", "c", "k")}
    body = json.loads((root / "vectors/section-2.json").read_text())["vectors"]
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

    # Both worlds, on one machine, via the PQSA_NO_KEM seam. The three rows are the ones whose
    # behaviour depends on whether an ML-KEM implementation is importable, and without care
    # only the absent branch existed, so the suite asserted "not_generatable" unconditionally
    # and started failing the moment the library was installed. A test that describes one
    # environment is a test that goes stale when the environment changes.
    KEM_ROWS = ("V2-01", "V2-11", "V2-13")

    print("\nwithout an ML-KEM: the rows are recorded absent, with the reason")
    root = tree(plan_of(**{"1": [], "2": list(KEM_ROWS), "2_9": [], "5": []}))
    rc, out = run(root, no_kem=True)
    case("they do not fail the run", rc, 0)
    body = json.loads((root / "vectors/section-2.json").read_text())["vectors"]
    case("all three are marked not_generatable",
         all("not_generatable" in body[k] for k in KEM_ROWS), True)
    case("and the reason names the missing library",
         all("kyber-py is not installed" in body[k]["not_generatable"] for k in KEM_ROWS), True)
    case("and says why it is recorded rather than synthesised",
         all("would pass" in body[k]["not_generatable"] for k in KEM_ROWS), True)
    case("the count distinguishes emitted from recorded",
         "0 vector(s) emitted, 3 recorded as not generatable" in out, True)
    case("and the run says the KEM is absent", "ML-KEM: absent" in out, True)

    print("\nwith an ML-KEM: the rows are emitted, and the KEM is checked against NIST first")
    root = tree(plan_of(**{"1": [], "2": list(KEM_ROWS), "2_9": [], "5": []}))
    rc, out = run(root)
    if "ML-KEM: absent" in out:
        case("SKIPPED -- no ML-KEM on this machine, so this branch cannot be exercised",
             True, True)
    else:
        case("the run passes", rc, 0)
        case("and reports the acceptance test against NIST's own file",
             "matched, 0 differed" in out, True)
        body = json.loads((root / "vectors/section-2.json").read_text())["vectors"]
        case("none of the three is marked not_generatable",
             any("not_generatable" in body[k] for k in KEM_ROWS), False)
        case("V2-11 records that decapsulation did NOT raise",
             body["V2-11"]["expect"]["decaps_raised"], False)
        case("and that implicit rejection gave a DIFFERENT secret, which is the whole point",
             body["V2-11"]["expect"]["tags_differ"], True)
        case("V2-13 closes the loop: the recipient's secret controls the sender's address",
             body["V2-13"]["expect"]["the_two_agree"] and
             body["V2-13"]["expect"]["secrets_agree"], True)
        case("the count distinguishes emitted from recorded",
             "3 vector(s) emitted, 0 recorded as not generatable" in out, True)

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

    # The unverifiable case, forced through the seam: generate WITH the KEM, check WITHOUT it.
    root = tree(plan_of(**{"1": [], "2": ["V2-01"], "2_9": [], "5": []}))
    _rc, gen_out = run(root)
    if "ML-KEM: absent" in gen_out:
        case("SKIPPED -- no ML-KEM here, so the unverifiable case cannot be staged", True, True)
    else:
        rc, out = run(root, "--check", no_kem=True)
        case("a row this process cannot rebuild does NOT fail the check", rc, 0)
        case("it is reported as not checked", "NOT CHECKED here" in out, True)
        case("and named", "V2-01" in out, True)
        case("and the manifest is skipped rather than called stale",
             "not compared" in out, True)
        case("and the word stale is not used for it", "FAIL" in out, False)

    # THE CONCLUSION, staged WITHOUT an ML-KEM. The block above needs kyber-py to generate a
    # real row and is skipped where it is absent -- which left the partial-success sentence
    # unreachable on exactly the machines that produce it. So the committed side is
    # fabricated here rather than generated: a committed row carrying an expectation, against
    # a run that records it not_generatable, is the same `unverified` state with no dependency.
    #
    # What this pins is honesty, not arithmetic. A run that SKIPPED rows and DECLINED the
    # manifest comparison must not conclude "every committed file matches a fresh
    # generation", and the generated public transcripts repeat whatever this prints -- so the
    # overclaim would reach a reader with no way to check it.
    root = tree(plan_of(**{"1": [], "2": ["V2-01"], "2_9": [], "5": []}))
    run(root, no_kem=True)
    f = root / "vectors/section-2.json"
    body = json.loads(f.read_text())
    if "not_generatable" in body["vectors"]["V2-01"]:
        body["vectors"]["V2-01"].pop("not_generatable")
        body["vectors"]["V2-01"]["expect"] = {"staged_by_the_self_test": True}
        f.write_text(json.dumps(body, indent=2) + "\n")
        rc, out = run(root, "--check", no_kem=True)
        case("a partial run still exits 0 -- an absent capability is not staleness", rc, 0)
        case("but it does NOT claim every committed file matches",
             "every committed file matches a fresh generation" in out, False)
        case("it concludes PARTLY instead", "OK, PARTLY" in out, True)
        case("and says plainly that this is not the full check",
             "not the full check" in out, True)
        case("and counts what it skipped",
             "1 row(s) and manifest.json were NOT compared" in out, True)

    print("\nthe manifest")
    root = tree(plan_of(**{"1": ["V1-01"], "2": [], "2_9": [], "5": []}))
    run(root)
    man = json.loads((root / "vectors/manifest.json").read_text())
    bad = [n for n, m in man["files"].items()
           if hashlib.sha256((root / "vectors" / n).read_bytes()).hexdigest() != m["sha256"]]
    case("its sha256 matches every emitted file", bad, [])
    case("it records where tier 1 came from",
         "ACVP-Server" in json.dumps(man["tier1_source"]), True)

    print("\nthe generator imports nothing from the implementation")
    src = TOOL.read_text(encoding="utf-8") + (TOOLS / "vecprim.py").read_text(encoding="utf-8")
    case("no `crates` reference in either file's code",
         [ln for ln in src.split("\n")
          if "crates" in ln and not ln.strip().startswith(("#", "*", "--", '"'))
          and "`crates/" not in ln], [])

    print("\nthe derivation constants are the specification's, not remembered")
    # Same shape as the wave-map case above: this delegates to a gate that does not ship with the
    # release, so in a release tree there is nothing to run. Announced, never silently passed.
    import subprocess as sp
    gate = TOOLS / "check_vector_strings.py"
    if not gate.is_file():
        print(f"  SKIPPED  {gate.name} is not present, so the constants cannot be checked "
              f"against the documents here. Expected in a release tree, a FINDING otherwise.")
    else:
        r = sp.run([sys.executable, str(gate), "."], capture_output=True, text=True, cwd=".")
        case("every constant is quoted in a spec document", r.returncode, 0)
    case("and the canonical rung names are the long form",
         (gv.RUNG_2, gv.RUNG_3),
         (b"schemeId 2 (direct KEM)", b"schemeId 3 (direct KEM, hybrid)"))
    case("and the hybrid separator is the one §2.9 states",
         gv.DS_HYBRID, b"pq-stealth/hybrid-payment/v1")
    # §5 says ikm = keygen_master, salt ABSENT. Passing the master as the salt instead was
    # the costly direction: an implementation following the spec fails the vector, and one following
    # the vector derives different recovery keys.
    case("keygen_seed passes the master as IKM, not as salt",
         vp.keygen_seed(bytes([0xA5]) * 32, 2, b"schemeId 2 (direct KEM)", 0, 96).hex()[:8],
         "0b696cff")

    print("\nevery rung name in a fixture's GIVEN block is the canonical one")
    # the second-site hazard: fixing the derivation while leaving the `given` fields means a runner that
    # derived from the fixture's own inputs reproduced the wrong seed stream while `expect`
    # held the right one. A fixture must be self-contained.
    root = tree(plan_of(**{"1": [], "2": [], "2_9": [], "5": ["V6-01", "V6-04"]}))
    run(root)
    body = json.loads((root / "vectors/section-5.json").read_text())["vectors"]
    names = json.dumps(body)
    case("no short rung label survives anywhere in the emitted §5 file",
         '"schemeId 2"' in names or '"schemeId 3"' in names, False)
    case("and the canonical names are present",
         "schemeId 2 (direct KEM)" in names
         and "schemeId 3 (direct KEM, hybrid)" in names, True)

    print("\na committed value is never replaced by a stub")
    # The failure this guards is concrete: a regeneration without
    # `kyber-py` replaced V2-01, V2-11 and V2-13 with `not_generatable` stubs, silently, because
    # a stub is a well-formed row. The only signal was a golden executed-case count in another
    # crate, in another language, asserted for an unrelated reason.
    #
    # Constructed by hand rather than by generating first, so this case does not need `kyber-py`
    # present to exercise the path that fires when it is absent.
    root = tree(plan_of(**{"1": [], "2": ["V2-01"], "2_9": [], "5": []}))
    committed = {
        "section": "§2",
        "wave": 1,
        "vectors": {"V2-01": {"claim": "c", "given": {"keygen_seed": "00" * 96},
                              "expect": {"ek": "ab" * 1184}}},
    }
    victim = root / "vectors/section-2.json"
    victim.write_text(json.dumps(committed, indent=2) + "\n", encoding="utf-8")
    before = victim.read_text(encoding="utf-8")

    rc, out = run(root, no_kem=True)
    case("a run that would downgrade a committed row exits 1", rc, 1)
    case("and names the row", "V2-01" in out, True)
    case("and says nothing was written", "Nothing was written" in out, True)
    case("and NOTHING WAS WRITTEN", victim.read_text(encoding="utf-8"), before)

    # And `--out` to a scratch tree is never a downgrade, because it overwrites nothing that
    # was committed. A guard keyed on the repository root instead of the destination reports
    # that a `--out "$(mktemp -d)"` run would destroy the repository's vectors -- wrong, and
    # the kind of false positive that gets a gate switched off.
    with tempfile.TemporaryDirectory() as scratch:
        rc, out = run(root, "--out", scratch, no_kem=True)
        case("--out to a scratch tree is allowed even without the KEM", rc, 0)
        case("and the committed file is untouched",
             victim.read_text(encoding="utf-8"), before)

    # The other direction: a row that has never been generated may absolutely be recorded as a
    # stub, and that is how the honest gaps are recorded. Refusing that too would make the
    # generator unable to describe its own limits.
    fresh = tree(plan_of(**{"1": [], "2": ["V2-01"], "2_9": [], "5": []}))
    rc, out = run(fresh, no_kem=True)
    case("but a first-time stub is allowed", rc, 0)
    body = json.loads((fresh / "vectors/section-2.json").read_text())["vectors"]
    case("and it carries the reason", "not_generatable" in body.get("V2-01", {}), True)

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

        # §1's offset digest, which every derived address in the ladder depends on.
        base, scalar, counter = vp.h_of_ss(bytes.fromhex(v1["V1-01"]["given"]["ss"]))
        case("the offset digest matches V1-01", base.hex(), v1["V1-01"]["expect"]["base"])
        case("and its reduction needs no retry, as the row states",
             counter, v1["V1-01"]["expect"]["counter"])
        case("and the offset equals the base when no retry was needed",
             f"{scalar:064x}", v1["V1-01"]["expect"]["offset"])

        # §5's announce seed: field ORDER, and the `kem_id` length prefix. Three mutations lived
        # here -- the index appended last, `kem_id` omitted, the prefix dropped -- and V6-05 pins
        # all three because it states the concatenation in its claim.
        v6 = json.loads((real / "vectors/section-5.json").read_text())["vectors"]["V6-05"]
        master = bytes.fromhex(v6["given"]["master"])
        for scheme_id, rung, i, n, key in [
            (2, b"schemeId 2 (direct KEM)", 0, 32, "schemeId_2_i0"),
            (2, b"schemeId 2 (direct KEM)", 1, 32, "schemeId_2_i1"),
            (3, b"schemeId 3 (direct KEM, hybrid)", 0, 64, "schemeId_3_i0"),
        ]:
            case(f"announce_seed matches V6-05 {key}",
                 vp.announce_seed(master, scheme_id, rung, i, n).hex(),
                 v6["expect"][key])
        case("kem_id is the length-prefixed name V6-05 states",
             vp.kem_id().hex(), v6["given"]["kem_id"])
        case("and its length prefix is present, so it is 18 bytes not 10",
             len(vp.kem_id()), v6["given"]["kem_id_length"])

        # The ACVP acceptance test must REPORT a disagreement rather than swallow it, and
        # `kem_encaps` must return `(ct, ss)` in the specification's order rather than the
        # library's. Both need a KEM; both mutations survived when this section did not exist.
        if not vp.have_kem():
            print("  SKIPPED  no ML-KEM here, so the oracle and the encaps order are unchecked "
                  "in this run, and nothing else checks them for you: install one "
                  "(`pip install --no-deps kyber-py==1.2.0`) and rerun -- a run without it is a "
                  "WEAKER run reporting the same OK.")
        else:
            # ONE case per family, not the whole vendored file. Pure-Python ML-KEM is seconds
            # per operation, `acvp_selftest` is called three times below, and this suite runs
            # once per mutation -- so the full file here cost about eight seconds of every
            # mutation of `vecprim.py` and `gen_vectors.py`, for no additional coverage. The
            # full-file run still happens: `gen_vectors.py` does it on every invocation, which is
            # where it belongs.
            full = json.loads((real / "vectors/tier1/ml-kem-768-acvp.json").read_text())
            t1 = dict(full)
            for family in ("keygen", "encapsulation", "decapsulation"):
                if full.get(family):
                    t1[family] = full[family][:1]
            case("the ACVP acceptance test finds no disagreement on a good library",
                 vp.acvp_selftest(t1), [])
            bad = json.loads(json.dumps(t1))
            if bad.get("keygen"):
                ek = bad["keygen"][0]["ek"]
                bad["keygen"][0]["ek"] = ("00" if ek[:2] != "00" else "11") + ek[2:]
                case("and DOES find one when a keyGen expectation is altered",
                     len(vp.acvp_selftest(bad)) >= 1, True)
            # BOTH halves of an encapsulation case, because the oracle reports them on two
            # separate lines and a mutation can silence either. Altering only the shared secret
            # left the ciphertext line unchecked, and the mutation that removed it survived.
            for field, label in (("c", "the ciphertext"), ("k", "the shared secret")):
                enc = json.loads(json.dumps(t1))
                if not enc.get("encapsulation"):
                    continue
                v = enc["encapsulation"][0][field]
                enc["encapsulation"][0][field] = ("00" if v[:2] != "00" else "11") + v[2:]
                case(f"and when an encapsulation case's {label} is altered",
                     len(vp.acvp_selftest(enc)) >= 1, True)
            # `(ct, ss)`, not `(ss, ct)`: the ciphertext is 1 088 bytes and the secret is 32, so
            # a swapped return is caught by length alone -- which is exactly why it must be
            # asserted somewhere rather than assumed obvious.
            ekb, _ = vp.kem_keygen(bytes(range(64)))
            ct, sec = vp.kem_encaps(ekb, bytes(range(32)))
            case("kem_encaps returns the ciphertext first, per the specification", len(ct), 1088)
            case("and the shared secret second", len(sec), 32)

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
    case("an unknown wave exits 2", run(tree(plan_of(**{"1": []})), "--wave", "9")[0], 2)
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
