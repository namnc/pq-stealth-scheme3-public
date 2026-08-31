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
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
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


def tree(
    plan: str,
    tier1: dict | None = "keep",
    *,
    ledger: dict | None = None,
    include_ledger: bool = True,
) -> Path:
    """A synthetic root. `tier1=None` omits ACVP; `include_ledger=False` omits the ledger."""
    tmp = Path(tempfile.mkdtemp())
    (tmp / "vectors" / "tier1").mkdir(parents=True)
    (tmp / "vectors" / "PLAN.md").write_text(plan, encoding="utf-8")
    if tier1 == "keep":
        real = ROOT / "vectors/tier1/ml-kem-768-acvp.json"
        (tmp / "vectors/tier1/ml-kem-768-acvp.json").write_text(
            real.read_text(encoding="utf-8"), encoding="utf-8")
    elif tier1 is not None:
        (tmp / "vectors/tier1/ml-kem-768-acvp.json").write_text(
            json.dumps(tier1), encoding="utf-8")
    if include_ledger:
        (tmp / "vectors/rederivation.json").write_text(
            json.dumps(ledger or {}), encoding="utf-8")
    return tmp


def run(root: Path, *extra: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(TOOL), *extra, str(root)],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


HDR = "| id | claim | given | expect | wrong |\n|---|---|---|---|---|\n"


def pin_section_1() -> None:
    """§1 against `vectors/section-1.json`, including retry *outputs*, not just `counter >= 1`."""
    v1 = json.loads((ROOT / "vectors/section-1.json").read_text(encoding="utf-8"))["vectors"]

    v = v1["V1-01"]
    base, scalar, counter = vp.h_of_ss(bytes.fromhex(v["given"]["ss"]))
    case("V1-01 offset digest", base.hex(), v["expect"]["base"])
    case("V1-01 counter", counter, v["expect"]["counter"])
    case("V1-01 offset", f"{scalar:064x}", v["expect"]["offset"])

    v = v1["V1-02"]
    base = bytes.fromhex(v["given"]["base"])
    case("V1-02 big-endian scalar",
         f"{int.from_bytes(base, 'big') % vp.N:064x}",
         v["expect"]["offset_big_endian"])
    case("V1-02 is not little-endian",
         f"{int.from_bytes(base, 'little') % vp.N:064x}" ==
         v["expect"]["offset_big_endian"], False)

    v = v1["V1-03"]
    scalar, counter = vp.reduce_to_scalar(bytes.fromhex(v["given"]["base"]))
    case("V1-03 counter", counter, v["expect"]["counter"])
    case("V1-03 offset", f"{scalar:064x}", v["expect"]["offset"])

    v = v1["V1-04"]
    scalar, counter = vp.reduce_to_scalar(bytes.fromhex(v["given"]["base"]))
    case("V1-04 counter", counter, v["expect"]["counter"])
    case("V1-04 offset", f"{scalar:064x}", v["expect"]["offset"])

    v = v1["V1-05"]
    scalar, counter = vp.reduce_to_scalar(bytes.fromhex(v["given"]["base"]))
    case("V1-05 counter", counter, v["expect"]["counter"])
    case("V1-05 offset", f"{scalar:064x}", v["expect"]["offset"])

    v = v1["V1-06"]
    digest = hashlib.sha256(
        vp.DS_OFFSET + bytes.fromhex(v["given"]["base"]) + bytes([1])
    ).digest()
    case("V1-06 single-byte counter", digest.hex(), v["expect"]["digest"])
    case("V1-06 is not u32be", digest.hex() == v["wrong"]["u32be"], False)
    case("V1-06 is not u64be", digest.hex() == v["wrong"]["u64be"], False)
    case("V1-06 is not ascii", digest.hex() == v["wrong"]["ascii"], False)

    v = v1["V1-07"]
    tag = vp.view_tag(bytes.fromhex(v["given"]["ss"]))
    case("V1-07 view tag", tag.hex(), v["expect"]["view_tag"])


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
    pin_section_1()

    print("\nthe row list comes from the plan, not from the generator")
    rc, out = run(tree(plan_of(**{"1": ["V1-01"], "2_9": []})))
    case("a plan naming one §1 row emits one", "§1: 1/1 slot(s)" in out, True)
    rc, out = run(tree(plan_of(**{"1": ["V1-01", "V1-01"], "2_9": []})))
    case("a plan listing the same id twice exits 1", rc, 1)
    case("and names the id and the count",
         "§1 V1-01 (2 times)" in out and "more than once" in out, True)
    # A row the plan lists and the builder does not build must FAIL, not be skipped.
    rc, out = run(tree(plan_of(**{"1": ["V1-01", "V1-99"], "2_9": []})))
    case("a plan row the generator cannot build exits 1", rc, 1)
    case("and it is named", "§1 V1-99" in out, True)
    case("and the message says silence is the worse outcome",
         "silence about a row" in out, True)

    print("\nthe supported group set is fail-closed")
    import gen_vectors as gv  # noqa: E402  -- always present; it is the tool under test
    case("the generator supports exactly the shipped sections", gv.GROUPS, ("1", "2.9"))
    rc, out = run(tree(plan_of(**{"1": ["V1-01"]})))
    case("a missing supported section exits 1", rc, 1)
    case("and names the missing section", "missing supported section(s): §2.9" in out, True)
    rc, out = run(tree(plan_of(**{"1": ["V1-01"], "2_9": [], "2": []})))
    case("an unsupported section exits 1", rc, 1)
    case("and names the unsupported section", "unsupported section(s): §2" in out, True)

    print("\na withdrawn or reserved plan row is neither emitted nor missing")
    # Group §1 is rendered LAST so the appended rows belong to it -- plan_of emits groups
    # in keyword order and a row line joins the group above it.
    plan = plan_of(**{"2_9": [], "1": ["V1-01"]})
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
    plan = plan_of(**{"2_9": [], "1": ["V1-01"]})
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
    rc, out = run(tree(plan_of(**{"1": ["V1-01"], "2_9": []}), tier1=None))
    case("a missing tier-1 file exits 2", rc, 2)
    case("and says tier 1 is NIST's", "does not compute it" in out, True)

    print("\nevery KEM value traces to the vendored file")
    root = tree(plan_of(**{"1": [], "2_9": ["V3-06a", "V3-08"]}))
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

    print("\n--check rejects edited, missing-row and absent-file states")
    root = tree(plan_of(**{"1": ["V1-01"], "2_9": []}))
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

    root = tree(plan_of(**{"1": ["V1-01"], "2_9": []}))
    run(root)
    f = root / "vectors/section-1.json"
    body = json.loads(f.read_text())
    body["section"] = "§9"
    f.write_text(json.dumps(body, indent=2) + "\n")
    rc, out = run(root, "--check")
    case("a wrong section label exits 1", rc, 1)
    case("and names the file and both labels",
         "section-1.json" in out and "§9" in out and "§1" in out, True)

    print("\nvecprim's primitives against committed fixtures")
    # §1 is pinned at the start of main() via `pin_section_1`, from ROOT rather than cwd.

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

    print("\nthe re-derivation ledger, and the rows it does NOT name")
    # The ledger used to carry an `absent` list naming the unwitnessed rows by hand. It was a
    # second copy of a fact the fixture set already determines, with no gate on it: add a
    # fixture, forget the edit, and the stale copy is the one implying the row was witnessed.
    # The generator computes the complement instead, so these cases are what make that
    # computation falsifiable.
    def with_ledger(body: dict | None) -> tuple[int, str]:
        root = tree(
            plan_of(**{"1": ["V1-01", "V1-02"], "2_9": []}),
            ledger=body,
            include_ledger=body is not None,
        )
        return run(root)

    rc, out = with_ledger(None)
    case("a missing ledger exits 2", rc, 2)
    case("and names the missing ledger", "no re-derivation ledger" in out, True)

    rc, out = with_ledger({"bytes_agree": ["V1-01", "V1-02"]})
    case("a ledger covering every row reports none unwitnessed",
         "2 of 2 shipped row(s) re-derived independently, 0 with NO outside witness" in out,
         True)
    case("and names no row as unwitnessed", "no witness:" in out, False)

    # THE CASE THE `absent` LIST EXISTED FOR, now automatic: a row nothing witnessed is
    # named without anyone having listed it.
    rc, out = with_ledger({"bytes_agree": ["V1-01"]})
    case("a row the ledger does not name is reported unwitnessed",
         "1 with NO outside witness" in out and "no witness: V1-02" in out, True)
    case("and that is REPORTED, not failed -- an unwitnessed row is a legitimate state",
         rc, 0)

    rc, out = with_ledger({"bytes_agree": ["V1-01", "V1-02"], "outcome_only": ["V9-99"]})
    case("a ledger naming a row no fixture has exits 1", rc, 1)
    case("and says which", "V9-99" in out and "vouches for nothing" in out, True)

    rc, out = with_ledger({"bytes_agree": ["V1-01", "V1-02"], "outcome_only": ["V1-01"]})
    case("a row classified twice exits 1", rc, 1)
    case("and says which", "V1-01" in out and "must be one thing" in out, True)

    # The four buckets are read by name, so a bucket lost from the tuple would silently
    # convert its rows to unwitnessed. This is the case that notices.
    rc, out = with_ledger({"ungeneratable": ["V1-01"], "bytes_disagree": ["V1-02"]})
    case("every witnessed bucket counts, not just the agreeing ones",
         "2 of 2 shipped row(s)" in out, True)

    print("\nusage")
    case("an unknown flag exits 2",
         run(tree(plan_of(**{"1": [], "2_9": []})), "--bogus")[0], 2)
    case("the withdrawn --wave flag is now just an unknown flag",
         run(tree(plan_of(**{"1": [], "2_9": []})), "--wave", "1")[0], 2)
    with tempfile.TemporaryDirectory() as t:
        case("a tree with no plan exits 2",
             subprocess.run([sys.executable, str(TOOL), t],
                            capture_output=True, text=True).returncode, 2)

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: gen_vectors and vecprim match the committed fixtures.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
