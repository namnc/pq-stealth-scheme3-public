"""Emit the tier-2 conformance vectors. **Imports nothing from the implementation.**

    gen_vectors.py [--out vectors] [root]

Exit 0 if every row the plan lists is either emitted or recorded as not generatable with a
reason, 1 if a row is neither, 2 on usage error.

WHY THIS FILE EXISTS AND WHAT IT MUST NOT DO. This generator comes ahead of any
cryptography, deliberately, for one reason: a fixture derived from the
code it validates tests self-consistency and nothing else. So it imports `tools/vecprim.py`
-- arithmetic written from the standards -- and the vendored NIST ACVP file, and nothing from
`crates/`.

**The row list is read off `vectors/PLAN.md`.** It is not written here. A generator with its own
list of ids can emit a set that disagrees with the plan and report success, and the plan is what
the author reads.

THE ML-KEM SUBSTITUTION, AND WHAT IT COSTS. The plan assumed the generator would use "one
ML-KEM library". None is installed and writing one is a project rather than a task -- 600-plus
lines of NTT and sampling, and a second unreviewed KEM in the tree. So this consumes NIST ACVP
`(d, z) -> ek` and `(ek, m) -> (c, k)` tuples instead, which is what the tier split already says.

That substitution has a cost and it is measured rather than glossed: **ACVP's keyGen and
encapsulation cases use different keys** -- checked: the two `ek` sets are disjoint
-- so a vector needing one key's seed AND a ciphertext to it cannot be built from ACVP alone.
Those rows are emitted as `not_generatable` with that reason, never with a synthesised `ct` or
`ss`. A fabricated KEM value in a conformance fixture would be worse than an absent one: it
would pass.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vecprim as vp  # noqa: E402

PLAN = Path("vectors/PLAN.md")
TIER1 = Path("vectors/tier1/ml-kem-768-acvp.json")

# The plan groups this generator builds, in emission order. Every invocation builds all of
# them: there is no partial run, which is what lets the manifest be REPLACED rather than
# merged below. `tools/test-gen-vectors.py` asserts the plan and this list agree -- two
# copies of a pacing decision is one too many, and the test is what stops them drifting.
GROUPS = ("1", "2.9")

GROUP = re.compile(r"^## (?:\d+[a-z]?)\.\s*§([\d.]+)")
ROW = re.compile(r"^\|\s*(V\d+-\d+[a-z]?)\s*\|")

# THE WITHDRAWN-ROW RULE, restated here because this file SHIPS and the coverage checker
# does not: a row whose CLAIM cell is struck through or says "no vector -- deliberately" is
# not a fixture. A reader should still see it, and a generator must neither emit it (that
# resurrects a requirement that no longer exists) nor report it missing (that demands a
# fixture for one). These two patterns are a SECOND COPY of `check_vector_coverage`'s -- the
# same trade the WAVES table makes, for the same reason: that checker pulls in tools about
# our own documents and stays in the authoring tree, so importing it here would break the
# shipped generator. `tools/test-gen-vectors.py` asserts the copies agree, pattern for
# pattern and row for row over the real plan, wherever both files are present.
#
# WITHDRAWN_CELL is case-sensitive and claim-cell-scoped on purpose: a live row's failure
# column may legitimately say "the withdrawn rule", and matching case-insensitively anywhere
# in the row read such a vector as withdrawn.
EMPTY_CELL = re.compile(r"no vector\s*[-—–]{1,2}\s*deliberately", re.I)
WITHDRAWN_CELL = re.compile(r"WITHDRAWN|~~")

# Inline code spans are blanked before the split, so a pipe inside backticks cannot shift
# every cell to its right -- the plan escapes literal pipes as `\|` inside code spans, and a
# raw split reads each one as a cell boundary.
CODE_SPAN = re.compile(r"`[^`]*`")


def claim_cell(line: str) -> str:
    """The second cell of a vector row, or "" if the row is malformed."""
    cells = CODE_SPAN.sub("", line).split("|")
    return cells[2].strip() if len(cells) > 2 else ""

# Read off §2.9 rather than remembered: a remembered `pq-stealth/hybrid/v1` — a string
# that appears nowhere in the specification — would derive every V3 row under the wrong
# constant. `tools/test-gen-vectors.py` checks that every constant below is quoted in the
# specification -- through an authoring-side gate when present, announced as SKIPPED when
# not -- because "I shortened it" is not a failure a reader of the emitted JSON can see.
DS_HYBRID = b"pq-stealth/hybrid-payment/v1"
# WHY A ROW IS `provisional`, in one place because it was in three and they drifted.
#
# The distinction that is easy to lose: "agreed" means two INDEPENDENT implementations
# converging in the wild — which is also how an unstated parameter masquerades as a
# chosen constant. What exists for these rows is this project's implementation plus
# a blinded re-derivation from this project's prose. Both are inside the project, so the
# constant is still a proposal -- and saying "no implementation has agreed" would send a
# reader looking for agreement that exists inside this project.
PROVISIONAL_WHY = ("NO OUTSIDE implementation has adopted it. This document's own implementation produces these bytes and an independent blinded re-derivation from the prose alone agreed on them, and neither is an outside party -- the constant is still a proposal")
def plan_rows(root: Path) -> dict[str, list[tuple[str, str]]]:
    """{group: [(row id, claim cell), ...]} read off the plan, in document order.

    The claim cell rides along so the caller can classify the row: a struck-through claim
    (WITHDRAWN, SUPERSEDED) or a "no vector -- deliberately" reservation is a row a reader
    should still see and a generator must neither emit nor report missing. Wave 1 never had
    one in its groups, which is why this function returned bare ids for as long as it did.
    """
    out: dict[str, list[tuple[str, str]]] = {}
    cur: str | None = None
    for ln in (root / PLAN).read_text(encoding="utf-8").split("\n"):
        m = GROUP.match(ln)
        if m:
            cur = m.group(1)
            out.setdefault(cur, [])
            continue
        m = ROW.match(ln)
        if m and cur:
            out[cur].append((m.group(1), claim_cell(ln)))
    return out


def not_a_fixture(cell: str) -> bool:
    """Whether a plan row's claim cell marks it withdrawn or reserved."""
    return bool(EMPTY_CELL.search(cell) or WITHDRAWN_CELL.search(cell))


def tier1(root: Path) -> dict:
    return json.loads((root / TIER1).read_text(encoding="utf-8"))


def hx(b: bytes) -> str:
    return b.hex()


# --------------------------------------------------------------------------------------
# §1 -- common to every schemeId. No KEM, no curve beyond the group order.
# --------------------------------------------------------------------------------------

def group_1() -> dict[str, dict]:
    v: dict[str, dict] = {}
    ss = bytes(range(32))
    base, scalar, counter = vp.h_of_ss(ss)
    v["V1-01"] = {
        "claim": "H(ss) = SHA256(DS_offset || ss), reduced",
        "given": {"ss": hx(ss)},
        "expect": {"base": hx(base), "offset": f"{scalar:064x}", "counter": counter},
    }

    # V1-02 pins BIG-ENDIAN. The `wrong` column is the whole point: a little-endian read gives
    # a different scalar, a different address, and funds nobody can spend. So the vector states
    # the wrong answer too, computed the wrong way on purpose.
    be = int.from_bytes(base, "big") % vp.N
    le = int.from_bytes(base, "little") % vp.N
    v["V1-02"] = {
        "claim": "every digest is big-endian",
        "given": {"ss": hx(ss), "base": hx(base)},
        "expect": {"offset_big_endian": f"{be:064x}"},
        "wrong": {"offset_little_endian": f"{le:064x}",
                  "note": "a different scalar, therefore a different address, therefore funds "
                          "the recipient cannot spend. Silent and total"},
    }

    zero = bytes(32)
    s0, c0 = vp.reduce_to_scalar(zero)
    v["V1-03"] = {
        "claim": "reduction MUST reject base = 0",
        "given": {"base": hx(zero)},
        "expect": {"counter": c0, "offset": f"{s0:064x}"},
        "wrong": {"counter": 0, "offset": f"{0:064x}", "note": "no range check"},
    }

    nb = vp.N.to_bytes(32, "big")
    sn, cn = vp.reduce_to_scalar(nb)
    v["V1-04"] = {
        "claim": "reduction MUST reject base = n",
        "given": {"base": hx(nb)},
        "expect": {"counter": cn, "offset": f"{sn:064x}"},
        "wrong": {"note": "accepted as valid; some libraries reduce mod n silently and "
                          "return 0"},
    }

    n1 = (vp.N - 1).to_bytes(32, "big")
    s1, c1 = vp.reduce_to_scalar(n1)
    v["V1-05"] = {
        "claim": "base = n - 1 is valid",
        "given": {"base": hx(n1)},
        "expect": {"counter": c1, "offset": f"{s1:064x}"},
        "wrong": {"note": "rejected -- an off-by-one in the bound loses a legitimate payment"},
    }

    # V1-06: the counter byte is ONE byte appended. The named wrong answers are a u32/u64
    # encoding and the ASCII digit, so all three are emitted.
    forced = zero  # reduces at counter 1, per V1-03
    one = hashlib.sha256(vp.DS_OFFSET + forced + bytes([1])).digest()
    v["V1-06"] = {
        "claim": "the counter byte is a single byte appended",
        "given": {"base": hx(forced), "counter": 1},
        "expect": {"digest": hx(one)},
        "wrong": {
            "u32be": hx(hashlib.sha256(vp.DS_OFFSET + forced + (1).to_bytes(4, "big")).digest()),
            "u64be": hx(hashlib.sha256(vp.DS_OFFSET + forced + (1).to_bytes(8, "big")).digest()),
            "ascii": hx(hashlib.sha256(vp.DS_OFFSET + forced + b"1").digest()),
        },
    }

    tag = vp.view_tag(ss)
    v["V1-07"] = {
        "claim": "view_tag = SHA256(DS_viewtag || ss)[0]",
        "given": {"ss": hx(ss)},
        "expect": {"view_tag": hx(tag), "view_tag_bytes": vp.VIEW_TAG_BYTES},
        "wrong": {
            "superseded_eight_byte_width":
                hx(hashlib.sha256(vp.DS_VIEWTAG + ss).digest()[:8]),
            "trailing_byte_of_own_digest":
                hx(hashlib.sha256(vp.DS_VIEWTAG + ss).digest()[31:]),
            "leading_byte_of_H_ss": hx(base[:1]),
            "note": "the tag was eight bytes until the announced stealthAddress became the "
                    "authoritative check (2.4 MUST) and the tag was narrowed to a prefilter; "
                    "an implementation carrying the old width matches nothing",
        },
    }
    return v
def group_2_9(t1: dict) -> dict[str, dict]:
    v: dict[str, dict] = {}
    en = t1["encapsulation"][0]
    ek = bytes.fromhex(en["ek"])
    ct = bytes.fromhex(en["c"])
    ss_pq = bytes.fromhex(en["k"])

    esk = int.from_bytes(bytes([0x22]) * 32, "big")
    epk_pt = vp.mul(esk)
    epk = vp.encode_compressed(epk_pt)
    v_seed = int.from_bytes(bytes([0x33]) * 32, "big")
    viewing_pk_ec = vp.encode_compressed(vp.mul(v_seed))

    # V3-04: ss_ec is the x-coordinate ALONE. The named wrong answers are the 65-byte point
    # and the 33-byte compressed form, so all three are emitted and they differ.
    shared_pt = vp.mul(esk, vp.decode_compressed(viewing_pk_ec))
    ss_ec = shared_pt[0].to_bytes(32, "big")
    v["V3-01"] = {"claim": "keygen seed is 128 B",
                  "given": {"lengths": [128, 96, 127]},
                  "expect": {"outcome": "outputs, then errors for 96 and 127"},
                  "wrong": {"note": "padding or truncating to 128 rather than rejecting; or "
                                    "accepting 96 bytes, which is a well-formed seed for a "
                                    "scheme with no EC half and is the likeliest port"}}
    spending_seed = bytes([0x11]) * 32
    offsets = [0, 40, 47, 5, 16, 20]
    planted = {}
    for off in offsets:
        buf = bytearray(bytes([0x44]) * 96)
        buf[off:off + 32] = spending_seed
        planted[off] = hx(bytes(buf))
    v["V3-02"] = {"claim": "the delegation check scans the 96-byte delegated object at all 65 "
                           "offsets",
                  "given": {"spending_seed": hx(spending_seed),
                            "delegated_objects_by_offset": planted,
                            "offsets_wholly_inside_a_half": [0, 40, 47],
                            "offsets_straddling_the_boundary": [5, 16, 20]},
                  "expect": {"outcome": "error, all six"},
                  "wrong": {"note": "scanning the two halves separately covers 34 offsets and "
                                    "accepts the straddling cases, placing the spending seed "
                                    "verbatim in bytes handed to a scanning service"}}
    clean = bytes([0x44]) * 96
    v["V3-02a"] = {"claim": "a keygen with no coincidence is accepted",
                   "given": {"spending_seed": hx(spending_seed), "delegated": hx(clean)},
                   "expect": {"outcome": "outputs, no error"},
                   "wrong": {"note": "rejecting valid keygens -- the positive control, "
                                     "without which V3-02 passes on an implementation that "
                                     "rejects everything"}}
    v["V3-03"] = {"claim": "meta is 1250 B and both points are validated",
                  "given": {"spending_pk": hx(vp.encode_compressed(
                      vp.mul(int.from_bytes(spending_seed, 'big')))),
                      "viewing_pk_ec_compact_0x05": hx(b"\x05" + viewing_pk_ec[1:])},
                  "expect": {"outcome": "error at decode"},
                  "wrong": {"note": "validating only spending_pk, which is the natural port "
                                    "of §2's decoder"}}
    v["V3-04"] = {"claim": "ss_ec is the x-coordinate alone",
                  "given": {"esk": f"{esk:064x}", "viewing_pk_ec": hx(viewing_pk_ec)},
                  "expect": {"ss_ec": hx(ss_ec), "length": 32},
                  "wrong": {"uncompressed_65": hx(vp.encode_uncompressed(shared_pt)),
                            "compressed_33": hx(vp.encode_compressed(shared_pt)),
                            "note": "a different ss, silently"}}

    ikm = ss_ec + ss_pq + epk + ct + viewing_pk_ec + ek
    ss = hashlib.sha3_256(DS_HYBRID + ikm).digest()
    v["V3-05"] = {"claim": "the domain separator is the FIRST input, neither appended nor "
                           "length-prefixed",
                  "provisional": True,
                  "provisional_because": PROVISIONAL_WHY,
                  "given": {"domain_separator": DS_HYBRID.decode(), "ikm": hx(ikm)},
                  "expect": {"ss": hx(ss)},
                  "wrong": {
                      "appended": hx(hashlib.sha3_256(ikm + DS_HYBRID).digest()),
                      "length_prefixed": hx(hashlib.sha3_256(
                          bytes([len(DS_HYBRID)]) + DS_HYBRID + ikm).digest()),
                      "note": "a different ss, silently. This is the parameter that replaced "
                              "the absent-salt requirement when the derivation became a "
                              "direct hash",
                  }}
    three = ss_ec + ss_pq + epk
    v["V3-06"] = {"claim": "IKM is exactly ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek",
                  "provisional": True,
                  "given": {"parts": {"ss_ec": hx(ss_ec), "ss_pq": hx(ss_pq), "epk": hx(epk),
                                      "ct": hx(ct), "viewing_pk_ec": hx(viewing_pk_ec),
                                      "ek": hx(ek)}},
                  "expect": {"ss": hx(ss)},
                  "wrong": {
                      "three_field_form": hx(hashlib.sha3_256(DS_HYBRID + three).digest()),
                      "note": "any other order, and any omission -> a different ss. The "
                              "three-field form is what both implementations produce today "
                              "and is the likeliest wrong answer",
                  }}
    ct2 = bytes.fromhex(t1["encapsulation"][1]["c"])
    v["V3-06a"] = {"claim": "ct is bound in",
                   "given": {"ct_a": hx(ct), "ct_b": hx(ct2),
                             "everything_else": "identical"},
                   "expect": {"ss_a": hx(ss),
                              "ss_b": hx(hashlib.sha3_256(
                                  DS_HYBRID + ss_ec + ss_pq + epk + ct2
                                  + viewing_pk_ec + ek).digest()),
                              "assertion": "different"},
                   "wrong": {"note": "the same ss -- the case SP 800-227 §4.6.3's argument "
                                     "turns on"}}
    vpk2 = vp.encode_compressed(vp.mul(int.from_bytes(bytes([0x55]) * 32, "big")))
    v["V3-06b"] = {"claim": "viewing_pk_ec is bound in",
                   "given": {"viewing_pk_ec_a": hx(viewing_pk_ec),
                             "viewing_pk_ec_b": hx(vpk2)},
                   "expect": {"ss_a": hx(ss),
                              "ss_b": hx(hashlib.sha3_256(
                                  DS_HYBRID + ss_ec + ss_pq + epk + ct + vpk2
                                  + ek).digest()),
                              "assertion": "different"},
                   "wrong": {"note": "the same ss, which is the identity binding absent from "
                                     "the old IKM"}}
    flipped = bytes([epk[0] ^ 0x01]) + epk[1:]
    v["V3-07"] = {"claim": "epk MUST be bound in",
                  "given": {"epk": hx(epk), "epk_parity_flipped": hx(flipped)},
                  "expect": {"ss_a": hx(ss),
                             "ss_b": hx(hashlib.sha3_256(
                                 DS_HYBRID + ss_ec + ss_pq + flipped + ct
                                 + viewing_pk_ec + ek).digest()),
                             "assertion": "different"},
                  "wrong": {"note": "the same ss -- the flipped point has the same "
                                    "x-coordinate, so without epk in the IKM this is a "
                                    "replay with a different-looking announcement"}}
    tag = vp.view_tag(ss)
    v["V3-08"] = {"claim": "wire shape",
                  "given": {"epk": hx(epk), "view_tag": hx(tag), "ct": hx(ct)},
                  "expect": {"ephemeralPubKey": hx(epk),
                             "metadata": hx(tag) + hx(ct),
                             "metadata_bytes": len(tag) + len(ct),
                             "payload_bytes": len(epk) + len(tag) + len(ct)},
                  "wrong": {"ct_then_view_tag": hx(ct) + hx(tag),
                            "note": "§2's field convention, which this variant does not use; "
                                    "or ct || view_tag, which puts the view tag at "
                                    "metadata[1088] -- the same length as the right answer, "
                                    "so no length check distinguishes it"}}
    v["V3-08a"] = {"claim": "the view tag is metadata[0]",
                   "given": {"metadata": hx(tag) + hx(ct)},
                   "expect": {"view_tag_at_index_0": hx(tag)},
                   "wrong": {"leading_byte_of_ct": hx(ct[:vp.VIEW_TAG_BYTES]),
                             "note": "reading the tag off ct rather than off metadata[0]. "
                                     "At one byte this still agrees 1 time in 256, so it is "
                                     "a scanner that misses most payments to it and finds "
                                     "the occasional one -- an intermittent fault, which is "
                                     "harder to chase than a clean empty scan"}}

    # ----------------------------------------------------------------------------------
    # V3-09..V3-16 -- RE-HOMED from the schemeId 2 set, which this tree no longer ships.
    #
    # Eight rules §2 states for THIS scheme had their only fixture in that set and lost it
    # with it; `vectors/PLAN.md` names each and where §2 states it. These rows put them
    # back. They are NEW VALUES and are listed under `absent` in
    # `vectors/rederivation.json`: the blinded re-derivation predates them and witnessed
    # none of them, which is exactly why they are fenced off here rather than filed in
    # among the witnessed rows above.
    #
    # Neither KEM-bearing row runs a KEM. V3-09 takes `ek` from ACVP keygen and V3-14
    # takes `(dk, ct, ss_pq)` from an ACVP decapsulation case whose `reason` is
    # `modified ciphertext` -- which is the implicit-rejection behaviour itself, oracled
    # by NIST rather than asserted by us.
    # ----------------------------------------------------------------------------------
    kg = t1["keygen"][0]
    kem_seed = bytes.fromhex(kg["d"]) + bytes.fromhex(kg["z"])
    v_ec_seed = bytes([0x33]) * 32
    assert vp.encode_compressed(vp.mul(int.from_bytes(v_ec_seed, "big"))) == viewing_pk_ec
    delegated = v_ec_seed + kem_seed
    assert not any(delegated[i:i + 32] == spending_seed for i in range(65)), \
        "§2.1's window scan would reject this fixture's own keygen seed"
    keygen_seed = spending_seed + delegated
    spending_pk = vp.encode_compressed(vp.mul(int.from_bytes(spending_seed, "big")))
    meta = spending_pk + viewing_pk_ec + bytes.fromhex(kg["ek"])
    v["V3-09"] = {"claim": "keygen MUST be deterministic in the seed -- the same 128 bytes "
                           "produce the same three outputs",
                  "given": {"keygen_seed": hx(keygen_seed),
                            "kem_seed_source": f"ML-KEM (d, z) of ACVP keygen tcId "
                                               f"{kg['tcId']}, so the ek below is NIST's "
                                               f"value and not this generator's"},
                  "expect": {"meta_address": hx(meta), "meta_address_bytes": len(meta),
                             "spending_pk": hx(spending_pk),
                             "viewing_pk_ec": hx(viewing_pk_ec),
                             "ek_at": "meta_address[66:1250]",
                             "tracking": hx(delegated), "tracking_bytes": len(delegated),
                             "master": hx(spending_seed)},
                  "wrong": {"note": "calling the KEM's randomness-taking keygen and ignoring "
                                    "kem_seed -- the entry point most ML-KEM APIs offer "
                                    "first. The meta-address is still well formed and "
                                    "registration still succeeds, so nothing fails until the "
                                    "owner restores from the seed, gets a different dk, and "
                                    "can decapsulate no payment ever made to the registered "
                                    "ek. Undetectable at keygen and total afterwards"}}

    v["V3-10"] = {"claim": "spending_seed and viewing_ec_seed MUST each be a valid secp256k1 "
                           "scalar -- error at keygen, per §2.7",
                  "given": {"seeds_128_B_differing_only_in_the_first_or_second_32": {
                      "spending_seed_0": hx(bytes(32)),
                      "spending_seed_n": f"{vp.N:064x}",
                      "spending_seed_n_minus_1": f"{vp.N - 1:064x}",
                      "viewing_ec_seed_0": hx(bytes(32))}},
                  "expect": {"outcome": "error, error, accepted, error"},
                  "wrong": {"note": "reducing the seed mod n instead of rejecting it. §1's "
                                    "counter-reduction is for the offset BASE, not for a "
                                    "seed: a library that reduces silently turns "
                                    "spending_seed = n into spending_seed = 0, and every "
                                    "payment to the resulting meta-address is spendable by "
                                    "anyone. n - 1 is the positive control -- an off-by-one "
                                    "in the bound rejects a legitimate seed"}}

    v["V3-11"] = {"claim": "decoding MUST reject a meta-address length other than 1250",
                  "given": {"lengths": [1249, 1250, 1251]},
                  "expect": {"outcome": "error, accepted, error"},
                  "wrong": {"note": "slicing [0:33], [33:66], [66:] with no length check. "
                                    "1251 then decodes with a trailing byte ignored and 1249 "
                                    "yields a 1183-byte ek that the KEM rejects much later, "
                                    "so the failure surfaces at the first payment rather "
                                    "than at decode"}}

    nonpoint_x = 5
    v["V3-12"] = {"claim": "33 bytes of the right length can still be a non-point -- both "
                           "points MUST be validated before the meta-address is used",
                  "given": {"viewing_pk_ec_nonpoint": hx(b"\x02" + nonpoint_x.to_bytes(32, "big")),
                            "why": f"x = {nonpoint_x} is the smallest x for which x^3 + 7 is "
                                   f"not a square mod p, so no y exists and this is 33 "
                                   f"well-formed bytes that are not a point",
                            "viewing_pk_ec_valid": hx(viewing_pk_ec)},
                  "expect": {"outcome": "error at decode, then accepted"},
                  "wrong": {"note": "checking the length and the 0x02/0x03 tag byte and "
                                    "storing the bytes. The ECDH that follows either throws "
                                    "from inside a curve library, far from the meta-address "
                                    "that caused it, or -- in a library that does not "
                                    "validate -- returns a value on the wrong curve"}}

    off_pt = vp.mul(scalar_from_ss := vp.h_of_ss(ss)[1])
    stealth_pt = vp.add(vp.decode_compressed(spending_pk), off_pt)
    address = vp.address_of(stealth_pt)
    uncompressed = vp.encode_uncompressed(stealth_pt)
    v["V3-13"] = {"claim": "address = keccak256(uncompressed(stealth_pk) without its 0x04 "
                           "prefix)[12..32]",
                  "given": {"stealth_pk_compressed": hx(vp.encode_compressed(stealth_pt)),
                            "stealth_pk_uncompressed": hx(uncompressed)},
                  "expect": {"address": hx(address), "eip55": vp.eip55(address)},
                  "wrong": {"keccak_of_compressed": hx(
                                vp.keccak256(vp.encode_compressed(stealth_pt))[12:32]),
                            "keccak_with_0x04_prefix": hx(
                                vp.keccak256(uncompressed)[12:32]),
                            "first_20_bytes_not_last_20": hx(
                                vp.keccak256(uncompressed[1:])[0:20]),
                            "note": "each is 20 well-formed bytes and each is a different "
                                    "address. The sender pays one of them and the recipient "
                                    "derives another; the payment is not lost to an error, "
                                    "it is lost to a chain address nobody holds a key for"}}

    dc = next(c for c in t1["decapsulation"] if c["reason"] == "modified ciphertext")
    dk_88 = bytes.fromhex(dc["dk"])
    ek_88 = dk_88[1152:2336]
    assert hashlib.sha3_256(ek_88).digest() == dk_88[2336:2368], \
        "ek is not embedded in this dk where FIPS 203 puts it"
    ct_foreign = bytes.fromhex(dc["c"])
    ss_pq_88 = bytes.fromhex(dc["k"])
    ss_foreign = hashlib.sha3_256(
        DS_HYBRID + ss_ec + ss_pq_88 + epk + ct_foreign + viewing_pk_ec + ek_88).digest()
    derived_tag = vp.view_tag(ss_foreign)
    announced_tag = bytes([derived_tag[0] ^ 0x01])
    v["V3-14"] = {"claim": "a view-tag mismatch is a skip -- and decapsulation does not fail",
                  "given": {"acvp_decapsulation_tcId": dc["tcId"],
                            "acvp_reason": dc["reason"],
                            "dk": "ACVP decapsulation tcId "
                                  f"{dc['tcId']}, vendored in vectors/tier1/",
                            "ek": hx(ek_88),
                            "ek_source": "dk[1152:2336] per FIPS 203's expanded key layout, "
                                         "checked against the H(ek) at dk[2336:2368]",
                            "announcement": {"ephemeralPubKey": hx(epk),
                                             "view_tag": hx(announced_tag),
                                             "ct": hx(ct_foreign)}},
                  "expect": {"decapsulation": "returns 32 bytes and does NOT fail",
                             "ss_pq": hx(ss_pq_88),
                             "ss": hx(ss_foreign),
                             "derived_view_tag": hx(derived_tag),
                             "outcome": "skip"},
                  "wrong": {"note": "scanning on whether Decaps errored. It never does -- "
                                    "ML-KEM rejects implicitly, which is what this NIST case "
                                    "shows: a ciphertext not produced for this key returns a "
                                    "pseudorandom secret and no error. An implementation "
                                    "that treats decapsulation as the ownership test matches "
                                    "every announcement ever published. Raising on the tag "
                                    "mismatch is the other error: announce() is "
                                    "permissionless, so an error path there is a scanner "
                                    "denial of service (§2.4)"}}

    v["V3-15"] = {"claim": "a malformed ct is a skip at the entry point, not an error",
                  "given": {"metadata_lengths": [1088, 1089, 1090],
                            "ephemeralPubKey_lengths": [32, 33]},
                  "expect": {"outcome": "skip for every length but 1089 / 33, which is "
                                        "processed"},
                  "wrong": {"note": "raising, or propagating a library exception. Anyone can "
                                    "call announce() with any bytes, so a scanner that errors "
                                    "on shape stops at the first announcement an attacker "
                                    "publishes -- and it costs the attacker one transaction. "
                                    "The 1089 case is the positive control"}}

    stealth_sk = (int.from_bytes(spending_seed, "big") + scalar_from_ss) % vp.N
    v["V3-16"] = {"claim": "a wallet SHOULD verify the derived key controls the derived "
                           "address, as a key-to-address relation",
                  "given": {"spending_sk": hx(spending_seed), "ss": hx(ss),
                            "offset": f"{scalar_from_ss:064x}"},
                  "expect": {"stealth_sk": f"{stealth_sk:064x}",
                             "address_from_the_key": hx(vp.address_of(vp.mul(stealth_sk))),
                             "address_from_the_point": hx(address),
                             "assertion": "identical"},
                  "wrong": {"note": "checking only that both paths produced bytes. They "
                                    "always do: spending_pk + offset*G and "
                                    "spending_sk + offset are two derivations that agree "
                                    "only if both are right, and a sign or byte-order slip "
                                    "in either yields a well-formed key for a different "
                                    "address. The payment is then presented as spendable and "
                                    "is not"}}
    return v


BUILDERS = {"1": lambda t1: group_1(), "2.9": group_2_9}


def canonical(row) -> str:
    """A row's canonical text, for comparing a fresh generation against a committed file.

    A FULL ROUND TRIP, not just a dump. `sort_keys` orders INTEGER keys numerically and the same
    keys, once parsed from JSON, are strings ordered lexicographically -- so `{0: .., 5: ..,
    16: ..}` dumps as 0, 5, 16 and its own parsed form dumps as 0, 16, 5. `V3-02`'s offset map has
    integer keys, and that alone reported it stale against a byte-identical file: a false positive
    in a staleness gate, which is the kind that teaches a reader to ignore it. Tuples are the same
    story in a different key -- a builder returning one dumps an array and reads back a list.

    **Hoisted out of `main`** so it can be tested directly. As a closure the only way to
    reach it is through the CLI, and a mutation removing the round trip would then survive
    the whole suite: nothing in the tree *emits* an integer key or a tuple by a path the
    self-test exercises, so the guard could not be shown to do anything. A guard that cannot
    be made to fail is a comment.
    """
    return json.dumps(json.loads(json.dumps(row)), sort_keys=True)


def refuse_to_downgrade(dest: Path, emitted: dict) -> list[str]:
    """A row that is committed WITH a value MUST NOT be replaced by a `not_generatable` stub.

    Without this guard, running this generator without `kyber-py` installed silently deletes
    the committed values for `V2-01`, `V2-11` and `V2-13` and leaves three "cannot be built"
    stubs in their place, with nothing in this tool objecting. The only other thing that
    notices is a golden executed-case count in the conformance runner's own integration
    test -- a different crate, a different language, an assertion written for an unrelated
    reason. Named rather than pathed, because a tree that ships the fixtures without the
    runner still needs this guard and would otherwise carry a pointer at nothing.

    A missing optional dependency must not be able to destroy committed evidence. Emitting a stub
    for a row that has NEVER been generated is fine and is how the four honest gaps are recorded;
    emitting one over a row that HAS a value is data loss, and it is silent because a stub is a
    perfectly well-formed row.
    """
    lost = []
    for name, body in emitted.items():
        # `dest`, not the repository root. The guard compares against what this run would
        # actually OVERWRITE, and `--out` exists so a run can regenerate into a scratch tree
        # without touching the committed set. Keying on the repo
        # instead made a temp-directory run report that it would destroy the repository's
        # vectors, which is both wrong and the kind of false positive that gets a gate disabled.
        old_path = dest / name
        if not old_path.exists():
            continue
        try:
            old = json.loads(old_path.read_text())["vectors"]
        except (ValueError, KeyError):
            continue
        for rid, new_row in body["vectors"].items():
            was = old.get(rid)
            if was is None:
                continue
            had_value = "expect" in was and was["expect"]
            now_stub = "not_generatable" in new_row
            if had_value and now_stub:
                lost.append(
                    f"{name}: {rid} is committed WITH a value and this run would replace it "
                    f"with a stub -- {new_row['not_generatable'][:70]}"
                )
    return lost


def main(argv: list[str]) -> int:
    args = argv[1:]
    out_dir = "vectors"
    # `--check` regenerates into memory and compares against what is committed, writing
    # nothing. A gate that
    # needs write access is a gate an independent reviewer cannot run.
    check_only = "--check" in args
    if check_only:
        args.remove("--check")
    if "--out" in args:
        k = args.index("--out")
        if k + 1 >= len(args):
            print("usage error: --out needs a value", file=sys.stderr)
            return 2
        out_dir = args[k + 1]
        del args[k:k + 2]
    bad = [a for a in args if a.startswith("-")]
    if bad or len(args) > 1:
        print(f"usage error: unexpected argument(s) {bad or args[1:]}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(args[0] if args else ".").resolve()
    if not (root / PLAN).is_file():
        print(f"usage error: no plan at {root / PLAN}", file=sys.stderr)
        return 2
    if not (root / TIER1).is_file():
        print(f"usage error: no vendored ACVP file at {root / TIER1}. Tier 1 is NIST's and "
              f"this generator does not compute it.", file=sys.stderr)
        return 2

    rows = plan_rows(root)
    t1 = tier1(root)

    # The ML-KEM library's acceptance test, run on EVERY invocation rather than once by hand.
    # It is not trusted because it is popular; it is trusted for exactly the NIST tuples it
    # reproduces, and a disagreement is a hard failure because every KEM-bearing row below
    # would otherwise be built on it silently. An absent library is reported, not failed --
    # those rows record themselves as not generatable with the reason.
    if vp.have_kem():
        disagreements = vp.acvp_selftest(t1)
        checks = (len(t1.get("keygen", []))
                  + 2 * len(t1.get("encapsulation", []))
                  + len(t1.get("decapsulation", [])))
        rejections = sum(1 for c in t1.get("decapsulation", [])
                         if c.get("reason") == "modified ciphertext")
        print(f"ML-KEM: kyber-py, acceptance test against the vendored NIST ACVP file -- "
              f"{checks - len(disagreements)} matched, {len(disagreements)} differed "
              f"({rejections} of them IMPLICIT-REJECTION cases)")
        # A count of zero rejection cases means the file lost them, and the oracle would then
        # be silently weakened: strong on keygen and encapsulation, blind on the
        # path `V2-11` and `V2-13` are emitted through.
        if rejections == 0:
            print("\nFAIL: the vendored ACVP file carries no `modified ciphertext` "
                  "decapsulation case, so implicit rejection -- the property this whole ladder "
                  "rests on -- has no external witness.", file=sys.stderr)
            return 1
        if disagreements:
            for d in disagreements:
                print(f"  {d}", file=sys.stderr)
            print("\nFAIL: the ML-KEM implementation disagrees with NIST. Every row below "
                  "would be built on it.", file=sys.stderr)
            return 1
    else:
        print("ML-KEM: absent (kyber-py not installed) -- rows needing a round trip will be "
              "recorded as not generatable")

    dest = root / out_dir
    dest.mkdir(parents=True, exist_ok=True)

    emitted = absent = 0
    manifest: dict[str, dict] = {}
    missing: list[str] = []
    skipped_rows: list[str] = []
    stale: list[str] = []
    unverified: list[str] = []
    print(f"groups: {', '.join('§' + g for g in GROUPS)}")
    for g in GROUPS:
        want = rows.get(g)
        if want is None:
            print(f"  §{g}: the plan has no group for it", file=sys.stderr)
            return 1
        built = BUILDERS[g](t1) if g in BUILDERS else {}
        # `slots`, in the coverage tool's vocabulary: the rows that are fixtures. A withdrawn
        # or reserved row is skipped by the same rule the coverage tool counts it under --
        # reporting one as "missing" would demand a fixture for a requirement that no longer
        # exists, and emitting one would resurrect it.
        slots = [rid for rid, cell in want if not not_a_fixture(cell)]
        skipped_rows.extend(f"§{g} {rid}" for rid, cell in want if not_a_fixture(cell))
        body: dict[str, dict] = {}
        for rid in slots:
            if rid in built:
                body[rid] = built[rid]
                if "not_generatable" in built[rid]:
                    absent += 1
                else:
                    emitted += 1
            else:
                missing.append(f"§{g} {rid}")
        # The plan is the authority on the row set, so a slot the plan lists and this file does
        # not build is a FINDING rather than a silent omission -- which is the whole reason the
        # ids are read off the plan instead of written here.
        f = dest / f"section-{g.replace('.', '_')}.json"
        # A row committed WITH a value must not be replaced by a `not_generatable` stub. Checked
        # BEFORE writing, and it aborts the whole run rather than skipping the file, because a
        # partial write leaves the manifest describing a tree that no longer exists.
        if not check_only:
            lost = refuse_to_downgrade(dest, {f.name: {"vectors": body}})
            if lost:
                print(f"\nFAIL: this run would DESTROY {len(lost)} committed vector(s):")
                for line in lost:
                    print(f"  {line}")
                print("\nNothing was written. Install the missing dependency and re-run, or "
                      "pass --out to a scratch directory if a downgrade is genuinely intended.")
                print("This failure mode is real: without this refusal, a regeneration "
                      "lacking `kyber-py` replaces V2-01, V2-11 and V2-13 with stubs, and "
                      "the only other thing that notices is a golden executed-case count "
                      "in another crate.")
                return 1
        blob = (json.dumps({"section": f"§{g}", "vectors": body},
                           indent=2) + "\n").encode("utf-8")
        if check_only:
            # Compared ROW BY ROW, not byte by byte, and the reason is that "differs" and
            # "cannot be checked here" are different findings. Without a KEM this process
            # cannot rebuild the round-trip rows at all, so a whole-file comparison calls a
            # perfectly current file stale -- the same conflation as scoring an unapplied
            # mutation as survived, or a skipped step as failed. A gate that cries stale
            # where it means unverifiable gets switched off.
            if not f.is_file():
                stale.append(f"{f.name}: absent")
                print(f"  §{g}: {f.name} ABSENT")
                continue
            try:
                committed = json.loads(f.read_text(encoding="utf-8")).get("vectors", {})
            except json.JSONDecodeError as e:
                stale.append(f"{f.name}: not valid JSON ({e})")
                print(f"  §{g}: {f.name} UNREADABLE")
                continue
            # Compared through `json.dumps`, NOT as Python objects. A tuple in a row
            # serialises to a JSON array and parses back as a list, so `dict != dict` on a
            # freshly built row against a parsed one reports a difference that does not
            # exist in the file — V3-02 reads as stale in a tree whose committed file is
            # byte-identical to a fresh generation. A false positive in a staleness gate
            # is the kind that teaches a reader to ignore it.
            norm = canonical

            diff = unchecked = 0
            for rid, fresh_row in body.items():
                if "not_generatable" in fresh_row and rid in committed \
                        and "not_generatable" not in committed[rid]:
                    # This run is the poorer one: the committed row was built with a
                    # capability this process lacks. Reported, never failed.
                    unverified.append(f"§{g} {rid}")
                    unchecked += 1
                elif rid not in committed:
                    stale.append(f"{f.name}: {rid} is missing from the committed file")
                    diff += 1
                elif norm(committed[rid]) != norm(fresh_row):
                    stale.append(f"{f.name}: {rid} differs from a fresh generation")
                    diff += 1
            for rid in committed:
                if rid not in body:
                    stale.append(f"{f.name}: {rid} is committed and the plan no longer lists "
                                 f"it as a fixture -- deleted, withdrawn or "
                                 f"reserved")
                    diff += 1
            state = "STALE" if diff else ("current, partly unverified" if unchecked
                                          else "current")
            print(f"  §{g}: {len(body)}/{len(slots)} slot(s), {f.name} {state}"
                  + (f" ({unchecked} row(s) this run cannot rebuild)" if unchecked else ""))
        else:
            f.write_bytes(blob)
            print(f"  §{g}: {len(body)}/{len(slots)} slot(s) written to {f.name}")
        entry = {"sha256": hashlib.sha256(blob).hexdigest(),
                 "rows_in_plan": len(want), "rows_present": len(body)}
        # Only stated when nonzero, so wave 1's entries -- whose groups have no such rows --
        # keep their exact committed bytes.
        if len(want) != len(slots):
            entry["rows_withdrawn_or_reserved"] = len(want) - len(slots)
        manifest[f.name] = entry

    # THE MANIFEST IS REPLACED, NOT MERGED, and that is a change from when this generator
    # ran one wave at a time. Then, a run rebuilt part of the set and had to carry the rest
    # of the committed manifest over or it would name fewer files than ship. Now every run
    # builds every group, so a carried-over entry can only be one thing: a file that has
    # stopped shipping, still named. That is not hypothetical -- the entries for
    # `section-2.json` and `section-5.json` outlived both files, and `--check` passed anyway,
    # because it verifies the files that are present rather than the names that are listed.
    # Sorted by file name so the byte order does not depend on iteration order.
    mf = dest / "manifest.json"
    merged: dict[str, dict] = dict(manifest)
    # The runner is named CONDITIONALLY, because this manifest ships into trees that do not
    # carry one: a single-scheme export drops the conformance crate, and a `_what` naming it
    # unconditionally would point a reader at a package their tree does not contain. What is
    # true in every tree is the generator's own `--check`.
    man = (json.dumps({"_what": "sha256 per emitted file. the conformance runner verifies "
                                "these where a tree carries one, and `gen_vectors.py --check` "
                                "re-derives every rebuildable row from the specification "
                                "either way -- fixture/manifest CONSISTENCY, not adversarial "
                                "integrity: this manifest lives in the same tree as the "
                                "fixtures, so an editor who changes a fixture can rehash it "
                                "here in the same commit. What it catches is the accidental "
                                "or incomplete edit. Protection against deliberate oracle "
                                "replacement comes from provenance -- the committed "
                                "generator, the blinded re-derivation, the NIST-oracled "
                                "rows.",
                       "tier1_source": t1["sources"],
                       "files": dict(sorted(merged.items()))}, indent=2)
           + "\n").encode("utf-8")
    if check_only:
        # The manifest is a hash per FILE, so it cannot be checked row-wise. It is therefore
        # only meaningful when this run rebuilt everything the committed set has; otherwise its
        # hashes legitimately differ and saying so would be the false "stale" again.
        if not mf.is_file():
            stale.append("manifest.json: absent")
        elif unverified:
            print("  manifest.json: not compared -- this run could not rebuild every committed "
                  "row, so its hashes would differ for a reason that is not staleness")
        elif mf.read_bytes() != man:
            stale.append("manifest.json: differs from a fresh generation")
    else:
        mf.write_bytes(man)

    print(f"\n{emitted} vector(s) emitted, {absent} recorded as not generatable")
    if skipped_rows:
        # Named, not just counted: a silently narrowed row set reads as full coverage.
        print(f"{len(skipped_rows)} plan row(s) withdrawn or reserved, not a generator's to "
              f"emit: {', '.join(skipped_rows)}")
    if missing:
        print(f"\nFAIL: {len(missing)} row(s) in the plan that this generator does not build, "
              f"and silence about a row the author will look for is the one outcome worse than "
              f"an absent vector:")
        for m in missing:
            print(f"  {m}")
        return 1
    if check_only and unverified:
        print(f"\n{len(unverified)} committed row(s) NOT CHECKED here, because this process "
              f"cannot rebuild them: {', '.join(unverified)}")
        print("  Reported, not failed: these rows were NOT checked in this run, and nothing "
              "else checks them for you. Install an ML-KEM implementation and re-run "
              "(`pip install --no-deps kyber-py==1.2.0`) for the full check. An absent "
              "capability is not a stale file, and a gate that conflated the two would be "
              "one somebody switches off.")
    if stale:
        print(f"\nFAIL: {len(stale)} committed row(s) or file(s) are not what the generator "
              f"produces:")
        for t in stale:
            print(f"  {t}")
        print(f"\nRegenerate with `python3 tools/gen_vectors.py` and commit the "
              "result.")
        return 1
    # The conclusion must not be wider than the run. A process that SKIPPED rows it could not
    # rebuild and DECLINED the manifest comparison, then concluded "every committed file
    # matches a fresh generation", claims a completeness it did not establish -- and the
    # generated public transcripts repeated the overclaim, which is where an outside reader
    # would have believed it. A partial success says which part.
    if check_only and unverified:
        print(f"OK, PARTLY: every row the plan lists is either emitted or "
              f"recorded as not generatable with a reason, and every REBUILDABLE committed "
              f"row matches a fresh generation — but {len(unverified)} row(s) and "
              f"manifest.json were NOT compared, because this process cannot rebuild them. "
              f"This run is not the full check.")
    else:
        print("OK: every row the plan lists is either emitted or recorded as "
              "not generatable with a reason"
              + (", and every committed file matches a fresh generation" if check_only
                 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
