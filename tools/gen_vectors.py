"""Emit the tier-2 conformance vectors. **Imports nothing from the implementation.**

    gen_vectors.py [--out vectors] [--wave 1] [root]

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

# Which plan groups belong to which wave. Kept in step with
# `check_vector_coverage.WAVES`, and `tools/test-gen-vectors.py` asserts the two agree -- two
# copies of a pacing decision is one too many, and the test is what stops them drifting.
WAVES = {1: ("1", "2.9", "5")}

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

# §5's canonical scheme names, quoted from the document. Shortening them changes every
# derived seed, which is why they are named constants and why they are gated.
RUNG_2 = b"schemeId 2 (direct KEM)"
RUNG_3 = b"schemeId 3 (direct KEM, hybrid)"
HOOK = ("A rejection cannot be reached by choosing inputs -- it needs a seed injected past the "
        "derivation, which is a harness hook and not a fixture. The plan records V1-08 as "
        "deliberately absent for the same reason and says so in terms.")


# §5's rung name for schemeId 2, as `V6-01`'s `given` block states it. Named once so the
# `wrong` column cannot silently use a different one — the drift a single definition
# exists to prevent.
RUNG_2_NAME = b"schemeId 2 (direct KEM)"

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


# --------------------------------------------------------------------------------------
# §5 -- seed derivation. HKDF and SHAKE256 only.
# --------------------------------------------------------------------------------------

def group_5() -> dict[str, dict]:
    v: dict[str, dict] = {}
    master = bytes([0xA5]) * 32
    # The CANONICAL names of §5, not shortened labels -- both halves, keygen and announce.
    s2 = vp.keygen_seed(master, 2, RUNG_2, 0, 96)
    s3 = vp.keygen_seed(master, 3, RUNG_3, 0, 128)
    v["V6-01"] = {
        "claim": "keygen_seed(schemeId, rung, j) with j = 0 on the normal path",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY,
        "given": {"keygen_master": hx(master),
                  "rungs": [{"schemeId": 2, "rung": RUNG_2.decode(), "L": 96},
                            {"schemeId": 3, "rung": RUNG_3.decode(), "L": 128}]},
        "expect": {"seed_schemeId_2": hx(s2), "seed_schemeId_3": hx(s3)},
        "wrong": {
            # A `fixed_L_32` generated with `b"schemeId 2"` -- the SHORTENED name --
            # changes TWO variables and is byte-identical to the first 32 bytes of
            # `shortened_rung_name`.
            # The label says "a fixed L = 32" and the value MUST test only that -- a value
            # generated with a shortened rung name as well would change two variables at once.
            #
            # The single-variable value exposes something a conflation would hide. HKDF-Expand is
            # counter-based, so its L = 32 output is a PREFIX of its L = 96 output for the same
            # info -- the right seed's first 32 bytes. **"L = 32 always" is therefore not
            # detectable by comparing content at all**; it is detectable only by LENGTH. An
            # implementation making that error fails the 96-byte check in `keygen`, never a
            # byte comparison, and a fixture implying otherwise misdirects the implementer it
            # is written for. `length_is_the_only_signal` records that.
            "fixed_L_32": hx(vp.keygen_seed(master, 2, RUNG_2_NAME, 0, 32)),
            "length_is_the_only_signal": (
                "the value above is the RIGHT seed's first 32 bytes -- HKDF-Expand is "
                "counter-based, so a short L is a prefix and not a different string. This "
                "error is caught by the seed-length check and by nothing else"
            ),
            "rung_name_omitted": hx(vp.keygen_seed(master, 2, b"", 0, 96)),
            "shortened_rung_name": hx(vp.keygen_seed(master, 2, b"schemeId 2", 0, 96)),
            "note": "a fixed L = 32; a supplied salt; omitting the scheme name, which "
                    "collides two schemes sharing a schemeId",
        },
    }
    # V6-02: independence. Asserted as a measurement over the emitted seeds rather than as
    # prose, so a runner can check it without trusting this comment.
    shared = max(
        (n for n in range(8, 33)
         if any(s2[i:i + n] in s3 for i in range(len(s2) - n + 1))),
        default=0,
    )
    v["V6-02"] = {
        "claim": "two schemes' keys from one master are independent",
        "provisional": True,
        "given": {"seeds": "the two of V6-01"},
        "expect": {"longest_shared_run_bytes": shared,
                   "assertion": "no run of 8 bytes or more appears in both"},
        "wrong": {"note": "deriving one from the other, or reusing one keygen seed under two "
                          "schemeIds"},
    }
    # V6-03 and V6-04 need a REJECTION to occur, and a rejection cannot be constructed by
    # choosing inputs: it needs a seed injected past the derivation, which is a harness hook
    # rather than a fixture. Same shape as V1-08, which the plan records as deliberately
    # absent for the same reason and says so in terms.
    v["V6-03"] = {
        "claim": "an ephemeral_seed that is not a valid scalar advances the index",
        "provisional": True,
        "not_generatable": HOOK,
    }
    # V6-04's second half IS derivable, and it is the half that matters: a rule that drew a
    # fresh keygen_master on rejection would change a FUNDED
    # scheme's keys. So the fixture pins that advancing one rung's index leaves every other
    # rung's seed byte-identical, and records that the trigger needs the hook.
    master = bytes([0xA5]) * 32
    a0 = vp.keygen_seed(master, 2, RUNG_2, 0, 96)
    a1 = vp.keygen_seed(master, 2, RUNG_2, 1, 96)
    b0 = vp.keygen_seed(master, 3, RUNG_3, 0, 128)
    v["V6-04"] = {
        "claim": "a rejected keygen seed advances the index of that (schemeId, rung) pair and "
                 "no other, and does not change keygen_master",
        "provisional": True,
        "partially_generatable": HOOK + " What IS pinned below is the consequence rather than "
                                        "the trigger, and it is the half a fresh-master rule "
                                        "gets wrong.",
        # The canonical names, not the short labels -- in `given` as well as in the
        # derivation. A `given` block carrying the short names while `expect` held seeds from
        # the long ones would hand a runner the wrong seed stream:
        # the long name gives 0b696cff, the short one 6ad22ee3.
        "given": {"keygen_master": hx(master),
                  "rung_a": RUNG_2.decode(), "rung_b": RUNG_3.decode()},
        "expect": {"rung_a_index_0": hx(a0), "rung_a_index_1": hx(a1),
                   "rung_b_index_0": hx(b0),
                   "assertion": "rung_a's index-1 seed differs from its index-0 seed, and "
                                "rung_b's index-0 seed is unchanged by either"},
        "wrong": {"note": "drawing a fresh keygen_master, which changes a funded scheme's keys"},
    }
    # V6-05: §5's ANNOUNCE seed. §5 specifies two derivations, and each needs its own
    # fixture -- a correction to one half prompts no check of the other. A derivation with no
    # fixture is a derivation nothing can disagree with.
    #
    # The `wrong` column is computed, not described: both entries are the actual digests the
    # two errors produce, so a runner can tell which mistake an implementation made rather than
    # only that it made one.
    a_i0 = vp.announce_seed(master, 2, RUNG_2, 0, 32)
    a_i1 = vp.announce_seed(master, 2, RUNG_2, 1, 32)
    b_i0 = vp.announce_seed(master, 3, RUNG_3, 0, 64)
    wrong_order = hashlib.shake_256(
        vp.DS_SENDER + master + (2).to_bytes(8, "big")
        + len(RUNG_2).to_bytes(8, "big") + RUNG_2 + (0).to_bytes(8, "big")
        + len(vp.kem_id()).to_bytes(8, "big") + vp.kem_id()).digest(32)
    wrong_no_kem = hashlib.shake_256(
        vp.DS_SENDER + master + (0).to_bytes(8, "big") + (2).to_bytes(8, "big")
        + len(RUNG_2).to_bytes(8, "big") + RUNG_2).digest(32)
    v["V6-05"] = {
        "claim": "announce_seed's field order is exactly DS || master || i || schemeId || "
                 "|rung| || rung || |kem_id| || kem_id, and kem_id is length-prefixed",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY,
        "given": {"master": hx(master),
                  "kem_id": hx(vp.kem_id()), "kem_id_length": len(vp.kem_id()),
                  "draws": [{"schemeId": 2, "rung": RUNG_2.decode(), "i": 0, "n": 32},
                            {"schemeId": 2, "rung": RUNG_2.decode(), "i": 1, "n": 32},
                            {"schemeId": 3, "rung": RUNG_3.decode(), "i": 0, "n": 64}]},
        "expect": {"schemeId_2_i0": hx(a_i0), "schemeId_2_i1": hx(a_i1),
                   "schemeId_3_i0": hx(b_i0),
                   "schemeId_3_split": {"ephemeral_seed": hx(b_i0[:32]),
                                        "encap_seed": hx(b_i0[32:])},
                   "indices_give_different_seeds": a_i0 != a_i1},
        "wrong": {
            "index_appended_last": hx(wrong_order),
            "kem_id_omitted": hx(wrong_no_kem),
            "note": "the two transpositions this row exists to forbid. Each yields "
                    "a well-formed seed of the right length that no conforming implementation "
                    "reproduces, so a sender using one draws a different ephemeral key and a "
                    "different KEM message from the same master and index",
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
                  "wrong": {"note": "accepting schemeId 2's 96-byte seed"}}
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
    return v


BUILDERS = {"1": lambda t1: group_1(), "5": lambda t1: group_5(),
            "2.9": group_2_9}


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
    out_dir, wave = "vectors", 1
    # `--check` regenerates into memory and compares against what is committed, writing
    # nothing. A gate that
    # needs write access is a gate an independent reviewer cannot run.
    check_only = "--check" in args
    if check_only:
        args.remove("--check")
    for flag, cast in (("--out", str), ("--wave", int)):
        if flag in args:
            k = args.index(flag)
            if k + 1 >= len(args):
                print(f"usage error: {flag} needs a value", file=sys.stderr)
                return 2
            val = cast(args[k + 1])
            out_dir, wave = (val, wave) if flag == "--out" else (out_dir, val)
            del args[k:k + 2]
    bad = [a for a in args if a.startswith("-")]
    if bad or len(args) > 1:
        print(f"usage error: unexpected argument(s) {bad or args[1:]}", file=sys.stderr)
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(args[0] if args else ".").resolve()
    if wave not in WAVES:
        print(f"usage error: no wave {wave}; known: {sorted(WAVES)}", file=sys.stderr)
        return 2
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
    print(f"wave {wave}: groups {', '.join('§' + g for g in WAVES[wave])}")
    for g in WAVES[wave]:
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
        blob = (json.dumps({"section": f"§{g}", "wave": wave, "vectors": body},
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
                                 f"it as a fixture for this wave -- deleted, withdrawn or "
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

    # THE MANIFEST IS MERGED, NOT REPLACED. One manifest describes every committed section
    # file across every wave, and this run rebuilt only one wave's -- so the other waves'
    # entries are carried over from the committed manifest rather than dropped. Without the
    # merge, a `--wave 2` run would emit a manifest naming two files and
    # `pqsa-conformance::load` would refuse the four wave-1 files as unlisted; the first
    # multi-wave regeneration is where a per-run manifest stops being a per-tree one.
    # Sorted by file name so the byte order does not depend on which wave ran last.
    mf = dest / "manifest.json"
    merged: dict[str, dict] = {}
    if mf.is_file():
        try:
            merged = json.loads(mf.read_text(encoding="utf-8")).get("files", {})
        except json.JSONDecodeError:
            merged = {}
    merged.update(manifest)
    # The runner is named CONDITIONALLY, because this manifest ships into trees that do not
    # carry one: a single-rung export drops the conformance crate, and a `_what` naming it
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
        print(f"\nRegenerate with `python3 tools/gen_vectors.py --wave {wave}` and commit the "
              "result.")
        return 1
    # The conclusion must not be wider than the run. A process that SKIPPED rows it could not
    # rebuild and DECLINED the manifest comparison, then concluded "every committed file
    # matches a fresh generation", claims a completeness it did not establish -- and the
    # generated public transcripts repeated the overclaim, which is where an outside reader
    # would have believed it. A partial success says which part.
    if check_only and unverified:
        print(f"OK, PARTLY: every row the plan lists for this wave is either emitted or "
              f"recorded as not generatable with a reason, and every REBUILDABLE committed "
              f"row matches a fresh generation — but {len(unverified)} row(s) and "
              f"manifest.json were NOT compared, because this process cannot rebuild them. "
              f"This run is not the full check.")
    else:
        print("OK: every row the plan lists for this wave is either emitted or recorded as "
              "not generatable with a reason"
              + (", and every committed file matches a fresh generation" if check_only
                 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
