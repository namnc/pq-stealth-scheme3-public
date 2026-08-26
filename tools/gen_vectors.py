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
WAVES = {1: ("1", "2", "2.9", "5"), 2: ("3", "3.12"), 3: ("4",)}

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

# schemeId 6's three canonical rung names, quoted from §5. All three share one schemeId,
# which is exactly why §5 derives seed streams per (schemeId, rung) pair -- the id alone
# does not separate them, and V6-15 exists to pin that it must not.
RUNG_6_L2 = b"schemeId 6 (Spirit, level 2)"
RUNG_6_L3 = b"schemeId 6 (Spirit, level 3)"
RUNG_6_L5 = b"schemeId 6 (Spirit, level 5)"

# §4 deviation 1's CRS input, quoted from the companion document. Keccak rather than SHAKE
# so the value is derivable on chain from a string literal; V6-09 re-derives the stated
# constant through vecprim's own permutation and commits the two plausible wrong digests.
CRS_STRING = b"pq-stealth/crs/v1"

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

# Wave 3's variant, because claiming wave 1's witnesses for these rows would assert evidence
# that does not exist: the blinded re-derivation has not run over this wave, and the rung
# implementation that now executes these rows was written with the fixtures already in the
# tree -- a second internal witness, not a blinded one. Both named honestly.
PROVISIONAL_WHY_W3 = ("NO OUTSIDE implementation has adopted it. These bytes are computed "
                      "from the specification prose by this generator, and the rung "
                      "implementation in this repository -- written after the fixtures "
                      "were committed, agreeing but not blinded -- executes the "
                      "generatable rows; the blinded re-derivation has not run over this "
                      "wave. An ACVP-accepted ML-KEM backs the rows that carry KEM "
                      "output. Two internal witnesses, neither an outside party: the "
                      "constant is still a proposal")

# Wave 2's rows carry the same sentence as wave 1's because the same two internal
# witnesses stand behind both waves: this project's implementation and a blinded
# re-derivation from the prose, agreed byte-for-byte.

# §3's separators, read off the document's own code blocks (§3.3, §3.5, §3.12) and gated the
# same way DS_HYBRID is: a constant here that the specification does not quote between
# delimiters fails the string gate `tools/test-gen-vectors.py` reports on.
DS_PAIRWISE_PQ = b"pq-stealth/pairwise-pq/v1"            # schemeId 4's channel key, §3.3
DS_PAIRWISE = b"pq-stealth/pairwise/v1"                  # schemeId 5's combiner, §3.12
DS_PAIRWISE_PAYMENT = b"pq-stealth/pairwise-payment/v1"  # both rungs' payment secret, §3.5

# §3.6's derivation width. A parameter of the DERIVATION and of no wire field: both parties
# MUST encode the counter at this width or they derive different payment secrets from the
# same channel key, silently.
NONCE_BYTES = 16

# THE FIXTURE'S CHOICE, NOT THE SPECIFICATION'S. §3.6 leaves SCAN_LOOKAHEAD provisional --
# an interoperability convention for the ecosystem to settle, MUST NOT be zero -- and says
# the vectors will carry a number marked as the fixture's choice. This is that number.
# Twenty is BIP44's address gap limit: the convention §3.6 cites as the exact precedent,
# agreed between wallets rather than derived from a distribution. For a parameter whose
# deciding evidence is agreement, a number with a precedent beats an invented one.
SCAN_LOOKAHEAD = 20

SCAN_LOOKAHEAD_WHY = (
    "the value is the FIXTURE'S choice, not the specification's: the document leaves "
    "SCAN_LOOKAHEAD to ecosystem agreement (it MUST NOT be zero) and a conformance vector "
    "needs a number. Twenty is BIP44's address-gap-limit convention, the precedent the "
    "document itself cites")


def ube_nonce(counter: int) -> bytes:
    """§3.5's `ubeN(counter)`: the counter, big-endian, at NONCE_BYTES -- derived on both
    sides, carried on no wire."""
    return counter.to_bytes(NONCE_BYTES, "big")


def pairwise_ss(k_pairwise: bytes, counter: int) -> bytes:
    """§3.5's payment secret: SHA256(separator || k_pairwise || ubeN(counter))."""
    return hashlib.sha256(DS_PAIRWISE_PAYMENT + k_pairwise + ube_nonce(counter)).digest()


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
        "claim": "view_tag = SHA256(DS_viewtag || ss)[0..8]",
        "given": {"ss": hx(ss)},
        "expect": {"view_tag": hx(tag), "view_tag_bytes": vp.VIEW_TAG_BYTES},
        "wrong": {
            "one_byte_only": hx(tag[:1]),
            "trailing_eight_of_own_digest":
                hx(hashlib.sha256(vp.DS_VIEWTAG + ss).digest()[24:]),
            "leading_eight_of_H_ss": hx(base[:8]),
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


# --------------------------------------------------------------------------------------
# §4 -- schemeId 6, wave 3. Structural and derivation rows only: every expectation here is
# arithmetic, hashing, or the KEM. The two rows whose expectations need spec-derived
# lattice output (V6-17, V6-18) are recorded ungenerated with the reason -- V6-03's
# discipline -- NEVER filled from an implementation or from the Spirit parity KATs, whose
# build reverts §4.1's mandatory per-one-time-key seed derivation (§4.2 states the
# incompatibility: the build with parity and the conforming build cannot be one build).
# --------------------------------------------------------------------------------------

# §4.2's category table: ML-DSA's k per security category, and the widths that follow.
# `ek` is ML-KEM-768's at EVERY category -- the KEM axis is settled as stock at all three
# levels, which is why one column of §4.2's table is constant.
S6_CATEGORIES = {2: 4, 3: 6, 5: 8}
S6_EK = 1184
S6_CT = 1088
S6_TAG = 8


def s6_t1(k: int) -> int:
    return k * 320


def s6_t0(k: int) -> int:
    return k * 416


def s6_meta(k: int) -> int:
    return s6_t1(k) + s6_t0(k) + S6_EK


NO_LATTICE = ("the expected bytes need ExpandA, the NTT and Power2Round derived from the "
              "specification prose independently of any implementation, and this generator "
              "has none of them. Filling the expectation from the implementation under test "
              "would make the suite a regression harness for one codebase; filling it from "
              "the Spirit parity KATs would pin the authors' C, whose build is "
              "non-conforming by construction. Specified, ungenerated, reason stated.")


def group_4() -> dict[str, dict]:
    v: dict[str, dict] = {}

    # V6-06: the keygen-seed length rule. The accept case carries no expected keys --
    # that is V6-17's slot, and the reason it is empty is stated there.
    v["V6-06"] = {
        "claim": "the keygen seed is dsa_seed(32) || kem_seed(64) = 96 B, and any other "
                 "length MUST be rejected",
        "provisional": True,
        "given": {"lengths": [95, 96, 97]},
        "expect": {"rejected": [95, 97], "accepted": [96],
                   "accepted_note": "acceptance is observable as no error; the derived "
                                    "keys' bytes are V6-17's slot"},
        "wrong": {"note": "accepting either neighbour; or the 192-byte "
                          "rho || mkgen_seed || kem_seed form, which carries a deployment "
                          "constant in a per-recipient seed and a Kyber layout this "
                          "specification discards"},
    }

    # V6-07: the delegation-window scan at this rung's own geometry -- the delegated
    # object is kem_seed alone, 64 B, 33 windows. Same planted-offset construction as
    # V4-07, self-checked: the spending seed appears at EXACTLY the planted window and
    # the clean control contains it nowhere.
    dsa_seed = bytes([0x42]) * 32

    def planted(offset: int) -> bytes:
        ks = bytearray(hashlib.shake_256(b"V6-07 filler " + bytes([offset])).digest(64))
        ks[offset:offset + 32] = dsa_seed
        out = bytes(ks)
        hits = [i for i in range(33) if out[i:i + 32] == dsa_seed]
        assert hits == [offset], f"planted seed leaked into windows {hits}"
        return out

    clean = hashlib.shake_256(b"V6-07 clean").digest(64)
    assert all(clean[i:i + 32] != dsa_seed for i in range(33))
    v["V6-07"] = {
        "claim": "a keygen where any 32-byte window of kem_seed equals dsa_seed MUST be "
                 "rejected -- the delegated object is 64 B, so 33 windows",
        "provisional": True,
        "given": {"dsa_seed": hx(dsa_seed),
                  "kem_seeds_by_offset": {"0": hx(planted(0)),
                                          "16": hx(planted(16)),
                                          "32": hx(planted(32))},
                  "clean_control": hx(clean)},
        "expect": {"planted_rejected": [0, 16, 32], "control_accepted": True},
        "wrong": {"note": "scanning 65 offsets -- §2.9's geometry, for a 96-byte delegated "
                          "object this rung does not have; or checking the two aligned "
                          "halves only, which misses offset 16"},
    }

    # V6-08: the dsa_seed expansion. SHAKE is an XOF, so a 96-byte squeeze is a PREFIX of
    # the 128-byte one -- "expanded only 96 bytes" is not a different stream, the error is
    # reading rhoprime from offset 0. The committed wrong value IS the right stream's
    # first 64 bytes; like V6-01's fixed_L_32, the content overlap is the point.
    d8 = hashlib.shake_256(b"V6-08 dsa_seed").digest(32)
    stream = hashlib.shake_256(d8).digest(128)
    v["V6-08"] = {
        "claim": "rho' || rhoprime || key = SHAKE256(dsa_seed, 128) at offsets 0, 32, 96; "
                 "rho' MUST be squeezed and discarded",
        "provisional": True,
        "given": {"dsa_seed": hx(d8)},
        "expect": {"stream_128": hx(stream),
                   "rho_discarded": hx(stream[:32]),
                   "rho_prime": hx(stream[32:96]),
                   "key": hx(stream[96:128])},
        "wrong": {"rhoprime_read_from_offset_0": hx(stream[:64]),
                  "key_read_from_offset_64": hx(stream[64:96]),
                  "note": "expanding 96 bytes and reading rhoprime || key from offset 0 -- "
                          "a different masking vector, and signatures that verify under "
                          "nothing. The values are the right stream's bytes 0..64 and "
                          "64..96: the mistake is the offset, not the stream"},
    }

    # V6-09: the CRS. Re-derived through vecprim's own keccak permutation rather than
    # quoted, so this generator is an independent witness to the constant §4 states. The
    # two wrong digests are computed so a runner can tell WHICH mistake was made.
    crs = vp.keccak256(CRS_STRING)
    v["V6-09"] = {
        "claim": "CRS_V1 = keccak256 of the literal below; a decoder reconstructs "
                 "pk_ds = CRS_V1 || t1, and rho is not on the wire",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY_W3,
        "given": {"literal": CRS_STRING.decode()},
        "expect": {"crs_v1": hx(crs)},
        "wrong": {"nist_sha3_256": hx(hashlib.sha3_256(CRS_STRING).digest()),
                  "shake256_32": hx(hashlib.shake_256(CRS_STRING).digest(32)),
                  "note": "NIST-padded SHA3 or SHAKE of the same literal -- each a "
                          "plausible 32 bytes no Ethereum node reproduces"},
    }

    # V6-10: the three-length rule. The reject list is computed from the same formulas as
    # the accept list -- off-by-one neighbours, the t1||ek totals that omit t0, the
    # rho-carrying forms, and this document's other meta-addresses.
    accepted = {str(c): s6_meta(k) for c, k in S6_CATEGORIES.items()}
    rejected = sorted({n for length in accepted.values() for n in (length - 1, length + 1)}
                      | {s6_t1(k) + S6_EK for k in S6_CATEGORIES.values()}
                      | {s6_meta(k) + 32 for k in S6_CATEGORIES.values()}
                      | {1217, 1250})
    v["V6-10"] = {
        "claim": "decoding MUST reject any length that is not the one its category names, "
                 "and a decoder MUST accept all three",
        "provisional": True,
        "given": {"lengths_offered": sorted(set(rejected) | set(accepted.values()))},
        "expect": {"accepted_by_category": accepted, "rejected": rejected},
        "wrong": {"note": "accepting the t1 || ek totals, which omit t0 and make every "
                          "payment unfindable; or a rho-carrying form 32 B longer; or "
                          "another scheme's meta-address length"},
    }

    # V6-11: the field offsets inside an accepted meta-address.
    v["V6-11"] = {
        "claim": "the meta-address is t1 || t0 || ek: t0 MUST be published, and the field "
                 "boundaries are k*320 and k*320 + k*416",
        "provisional": True,
        "given": {"k_by_category": {str(c): k for c, k in S6_CATEGORIES.items()}},
        "expect": {str(c): {"t1_end": s6_t1(k),
                            "t0_end": s6_t1(k) + s6_t0(k),
                            "ek_bytes": S6_EK,
                            "total": s6_meta(k)}
                   for c, k in S6_CATEGORIES.items()},
        "wrong": {"note": "omitting t0 -- OPKGen and Track form t' from full-precision t, "
                          "so a sender holding t1 alone pays an address nobody can find"},
    }

    # V6-12: the announcement wire split, with the reference's own layout as the computed
    # wrong answer -- 24 B larger per category, and its first 32 bytes are a recipient tag.
    v["V6-12"] = {
        "claim": "the announcement is t1_ot in ephemeralPubKey (k*320 B) and "
                 "view_tag || ct in metadata (1096 B), and MUST NOT carry rho",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY_W3,
        "given": {"metadata_layout": "view_tag(8) || ct(1088)"},
        "expect": {str(c): {"ephemeralPubKey_bytes": s6_t1(k),
                            "metadata_bytes": S6_TAG + S6_CT,
                            "payload_bytes": s6_t1(k) + S6_TAG + S6_CT}
                   for c, k in S6_CATEGORIES.items()},
        "wrong": {"reference_layout_bytes":
                      {str(c): 32 + s6_t1(k) + S6_CT for c, k in S6_CATEGORIES.items()},
                  "note": "the reference's opk_ds || ct, with rho on the wire and no view "
                          "tag -- 24 B larger per category, and its first 32 bytes are a "
                          "recipient tag a memcmp links with no key material"},
    }

    # V6-13: the view-tag formula, same digest and domain separator as §1's.
    ss13 = hashlib.shake_256(b"V6-13 ss").digest(32)
    tag13 = vp.view_tag(ss13)
    v["V6-13"] = {
        "claim": "view_tag = SHA256 of the view-tag domain separator || ss, first 8 bytes, "
                 "and it sits FIRST in metadata",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY_W3,
        "given": {"ss": hx(ss13), "ds": vp.DS_VIEWTAG.decode()},
        "expect": {"view_tag": hx(tag13), "position": "metadata[0..8]"},
        "wrong": {"one_byte_tag": hx(tag13[:1]),
                  "shake_tag": hx(hashlib.shake_256(vp.DS_VIEWTAG + ss13).digest(8)),
                  "note": "the pre-widening one-byte width, which leaves the most "
                          "expensive per-announcement work in the ladder running on one "
                          "foreign announcement in 256; or SHAKE256 in place of SHA256"},
    }

    # V6-14: the sender chain, deterministic from encap_seed. Needs a real KEM round trip.
    if vp.have_kem():
        dz14 = hashlib.shake_256(b"V6-14 dz").digest(64)
        ek14, _ = vp.kem_keygen(dz14)
        m14 = hashlib.shake_256(b"V6-14 encap_seed").digest(32)
        ct14, ss14 = vp.kem_encaps(ek14, m14)
        v["V6-14"] = {
            "claim": "the sender chain is deterministic from encap_seed: (ct, ss) = "
                     "ML-KEM-768.Encaps(ek, encap_seed), view_tag from ss",
            "provisional": True,
            "given": {"kem_seed_dz": hx(dz14), "ek": hx(ek14), "encap_seed": hx(m14)},
            "expect": {"ct": hx(ct14), "ct_bytes": len(ct14),
                       "ss": hx(ss14), "view_tag": hx(vp.view_tag(ss14))},
            "wrong": {"note": "drawing fresh randomness instead of the derandomised form, "
                              "which makes announcements irreproducible from the seed "
                              "record and unauditable against §5's stream"},
        }
    else:
        v["V6-14"] = {"claim": "the sender chain is deterministic from encap_seed",
                      "provisional": True,
                      "not_generatable": vp.KEM_ABSENT}

    # V6-15: §5's announce-seed streams under the three canonical rung names. The computed
    # wrong value is the natural error: one level-less name shared by all three levels,
    # which collapses three streams into one because the schemeId alone cannot separate
    # them.
    m15 = hashlib.shake_256(b"V6-15 master").digest(32)
    rungs15 = (("level_2", RUNG_6_L2), ("level_3", RUNG_6_L3), ("level_5", RUNG_6_L5))
    seeds15 = {f"{label}_i{i}": vp.announce_seed(m15, 6, rung, i, 32)
               for label, rung in rungs15 for i in (0, 1)}
    assert len(set(seeds15.values())) == 6
    v["V6-15"] = {
        "claim": "the announce seed is drawn per §5 under each of schemeId 6's three "
                 "canonical rung names, and distinct indices give distinct seeds",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY_W3,
        "given": {"master": hx(m15),
                  "rungs": [rung.decode() for _, rung in rungs15],
                  "indices": [0, 1]},
        "expect": {**{k: hx(s) for k, s in seeds15.items()},
                   "six_distinct": True},
        "wrong": {"levelless_rung_name_i0": hx(vp.announce_seed(m15, 6, b"schemeId 6",
                                                                0, 32)),
                  "note": "one level-less rung name shared by the three levels, which "
                          "collapses their seed streams into one -- §5 requires "
                          "independence per (schemeId, rung) pair, and the schemeId alone "
                          "does not separate them because all three levels share it"},
    }

    # V6-16: the §4.5 skip ladder. Cases (a) and (b) fire on lengths, BEFORE any KEM use;
    # case (c) is V2-11's foreign-announcement construction at this rung's shape, so it
    # needs the KEM. The t1_ot in case (c) is arbitrary bytes, deliberately and stated:
    # the skip fires at the tag, before anything reads it.
    if vp.have_kem():
        our_dz = hashlib.shake_256(b"V6-16 our dz").digest(64)
        foreign_dz = hashlib.shake_256(b"V6-16 foreign dz").digest(64)
        foreign_ek, _ = vp.kem_keygen(foreign_dz)
        m16 = hashlib.shake_256(b"V6-16 encap_seed").digest(32)
        ct16, senders_ss = vp.kem_encaps(foreign_ek, m16)
        ours_ss = vp.kem_decaps(our_dz, ct16)
        announced16 = vp.view_tag(senders_ss)
        derived16 = vp.view_tag(ours_ss)
        assert announced16 != derived16
        t1_ot_arbitrary = hashlib.shake_256(b"V6-16 t1_ot filler").digest(s6_t1(4))
        v["V6-16"] = {
            "claim": "the §4.5 skip ladder: wrong metadata length, wrong-category "
                     "ephemeralPubKey length, view-tag mismatch -- each is a skip, and "
                     "every negative outcome MUST be a skip, never an error",
            "provisional": True,
            "given": {
                "case_a_metadata_bytes": S6_TAG + S6_CT - 1,
                "case_b": {"our_category": 2,
                           "ephemeralPubKey_bytes": s6_t1(S6_CATEGORIES[3])},
                "case_c": {"our_kem_seed_dz": hx(our_dz),
                           # The sender side is committed too, so the row reproduces from
                           # this file alone: encapsulating to foreign_ek with encap_seed
                           # yields the metadata below. Without these, the announced tag's
                           # justification lives only in generator internals.
                           "foreign_kem_seed_dz": hx(foreign_dz),
                           "foreign_ek": hx(foreign_ek),
                           "encap_seed": hx(m16),
                           "ephemeralPubKey": hx(t1_ot_arbitrary),
                           "ephemeralPubKey_note": "arbitrary bytes, deliberately: the "
                                                   "skip fires at the tag, before "
                                                   "anything reads t1_ot",
                           "metadata": hx(announced16 + ct16)},
            },
            "expect": {"case_a": "not ours, skip -- fires on metadata length, before "
                                 "decapsulation",
                       "case_b": "not ours, skip -- fires on the category length check, "
                                 "before decapsulation",
                       "case_c_derived_ss": hx(ours_ss),
                       "case_c_derived_view_tag": hx(derived16),
                       "case_c": "not ours, skip -- decapsulation does NOT fail, the tag "
                                 "comparison does",
                       "errors_raised": 0},
            "wrong": {"note": "an error on any of the three -- announce() is "
                              "permissionless, so an error path is a denial of service a "
                              "stranger can trigger; or running Track at the wrong "
                              "category, which the ladder's second line exists to "
                              "prevent"},
        }
    else:
        v["V6-16"] = {"claim": "the §4.5 skip ladder: three skips, never an error",
                      "provisional": True,
                      "not_generatable": vp.KEM_ABSENT}

    # V6-17 and V6-18: the two lattice-dependent expectations, recorded rather than filled.
    v["V6-17"] = {
        "claim": "the meta-address a conforming keygen derives from an accepted 96-byte "
                 "seed, in bytes",
        "provisional": True,
        "not_generatable": NO_LATTICE,
    }
    v["V6-18"] = {
        "claim": "a conforming announcement for a known key is retained -- Decaps, tag "
                 "match, Track true",
        "provisional": True,
        "not_generatable": NO_LATTICE,
    }

    return v


# --------------------------------------------------------------------------------------
# §2 and §2.9 -- what is reachable with the curve plus ACVP as given data
# --------------------------------------------------------------------------------------

NO_KEM = ("ACVP's keyGen and encapsulation cases use disjoint keys, so this row needs one "
          "key's 64-byte (d, z) seed AND a ciphertext encapsulated to it. That is an ML-KEM "
          "implementation, not a lookup. Recorded rather than synthesised: a fabricated ct or "
          "ss in a conformance fixture would pass.")


def group_2(t1: dict) -> dict[str, dict]:
    v: dict[str, dict] = {}
    kg = t1["keygen"][0]
    en = t1["encapsulation"][0]
    ek_seed = bytes.fromhex(kg["d"] + kg["z"])
    ek = bytes.fromhex(kg["ek"])

    spending_seed = bytes([0x11]) * 32
    spending_pk = vp.encode_compressed(vp.mul(int.from_bytes(spending_seed, "big")))

    if vp.have_kem():
        # The full round trip, from a 96-byte keygen seed. Determinism is asserted by deriving
        # TWICE and comparing, not by claiming it: a generator that computes once and states
        # "deterministic" has tested nothing.
        seed96 = spending_seed + ek_seed
        ek_a, _ = vp.kem_keygen(seed96[32:])
        ek_b, _ = vp.kem_keygen(seed96[32:])
        v["V2-01"] = {
            "claim": "keygen seed is 96 B and keygen is deterministic",
            "given": {"keygen_seed": hx(seed96),
                      "split": "spending_seed(32) || kem_seed(64)",
                      "kem_seed_source": f"ACVP keyGen tcId {kg['tcId']}"},
            "expect": {"spending_pk": hx(spending_pk), "ek": hx(ek_a),
                       "ek_length": len(ek_a),
                       "deterministic": ek_a == ek_b,
                       "tracking_key_is_the_dz_seed": hx(ek_seed),
                       "tracking_key_length": len(ek_seed)},
            "wrong": {"expanded_dk_length": 2400,
                      "note": "a tracking key of 2 400 bytes -- the EXPANDED dk, which §1 "
                              "forbids as the representation; the 64-byte (d, z) seed is what "
                              "makes the delegated object 64 bytes and not 2 400. Also: "
                              "splitting the 96 bytes as 64 || 32"}}
        assert ek_a == ek, "kem_keygen disagrees with the ACVP ek for the same (d, z)"
    else:
        v["V2-01"] = {"claim": "keygen seed is 96 B and keygen is deterministic",
                      "not_generatable": vp.KEM_ABSENT,
                      "partial": {"kem_seed_dz": hx(ek_seed), "ek_from_acvp": hx(ek)}}
    v["V2-02"] = {"claim": "MUST reject any other keygen-seed length",
                  "given": {"lengths": [95, 97, 0]},
                  "expect": {"outcome": "error at keygen, all three"},
                  "wrong": {"note": "padding or truncating to 96"}}
    v["V2-03"] = {"claim": "spending_seed MUST be a valid scalar",
                  "given": {"spending_seeds": [hx(bytes(32)), hx(vp.N.to_bytes(32, "big"))]},
                  "expect": {"outcome": "error at keygen, both"},
                  "wrong": {"note": "accepted; SecretKey::from_slice catches one of these but "
                                    "not both in every library"}}
    # V2-04: the window scan. `spending_seed` planted at offset 17 of the 64-byte kem_seed --
    # a prefix-only comparison passes this, and the tracking key then carries the master
    # spending key verbatim.
    planted = bytearray(ek_seed)
    planted[17:49] = spending_seed
    v["V2-04"] = {"claim": "delegation check is a 32-byte window scan",
                  "given": {"spending_seed": hx(spending_seed),
                            "kem_seed": hx(bytes(planted)), "planted_at_offset": 17},
                  "expect": {"outcome": "error at keygen"},
                  "wrong": {"note": "accepted. A prefix-only comparison passes this, and the "
                                    "tracking key then contains the master spending key "
                                    "verbatim"}}
    meta = spending_pk + ek
    v["V2-05"] = {"claim": "meta = spending_pk(33) || ek(1184) = 1217 B",
                  "given": {"spending_pk": hx(spending_pk),
                            "ek": hx(ek), "ek_source": f"ACVP keyGen tcId {kg['tcId']}"},
                  "expect": {"meta_address": hx(meta), "length": len(meta)},
                  "wrong": {"swapped": hx(ek + spending_pk),
                            "note": "field order swapped; a length prefix added"}}
    v["V2-06"] = {"claim": "decode MUST reject any other length",
                  "given": {"lengths": [1216, 1218]},
                  "expect": {"outcome": "error at decode, both"},
                  "wrong": {"note": "trailing bytes ignored"}}
    v["V2-07"] = {"claim": "tag MUST be 0x02/0x03 only",
                  "given": {"compact_0x05": hx(b"\x05" + spending_pk[1:]),
                            "same_point_compressed": hx(spending_pk)},
                  "expect": {"outcome": "error at decode"},
                  "wrong": {"note": "accepted. The RustCrypto sec1 stack canonicalises 0x05 "
                                    "to the same point, so one key gets two on-chain "
                                    "encodings. The two references disagreed on this"}}
    v["V2-08"] = {"claim": "33 bytes of right length can still be a non-point",
                  "given": {"bytes": hx(b"\x02" + b"\xff" * 32)},
                  "expect": {"outcome": "error at decode"},
                  "wrong": {"note": "accepted, then a curve operation on garbage"}}
    pt = vp.decode_compressed(spending_pk)
    addr = vp.address_of(pt)
    v["V2-09"] = {"claim": "address = keccak256(uncompressed(pk)[1..])[12..32]",
                  "given": {"stealth_pk": hx(spending_pk)},
                  "expect": {"address": "0x" + hx(addr), "eip55": vp.eip55(addr)},
                  "wrong": {
                      "with_0x04_prefix":
                          "0x" + hx(vp.keccak256(vp.encode_uncompressed(pt))[12:]),
                      "first_20_bytes":
                          "0x" + hx(vp.keccak256(vp.encode_uncompressed(pt)[1:])[:20]),
                      "sha3_not_keccak":
                          "0x" + hashlib.sha3_256(
                              vp.encode_uncompressed(pt)[1:]).digest()[12:].hex(),
                  }}
    ct = bytes.fromhex(en["c"])
    ss_pq = bytes.fromhex(en["k"])
    tag = vp.view_tag(ss_pq)
    v["V2-10"] = {"claim": "announcement is ct in ephemeralPubKey, view_tag (8 B) in metadata",
                  "given": {"ct": hx(ct), "ss": hx(ss_pq),
                            "source": f"ACVP encapsulation tcId {en['tcId']}"},
                  "expect": {"ephemeralPubKey": hx(ct), "metadata": hx(tag),
                             "metadata_bytes": len(tag),
                             "payload_bytes": len(ct) + len(tag)},
                  "wrong": {"swapped_fields": {"ephemeralPubKey": hx(tag),
                                               "metadata": hx(ct)},
                            "one_byte_metadata": hx(tag[:1]),
                            "note": "the two fields swapped -- which is §3's convention and "
                                    "is wrong here; or a one-byte metadata, which no "
                                    "scheme in the specification emits"}}
    if vp.have_kem():
        # A FOREIGN announcement: encapsulated to somebody else's ek, decapsulated with ours.
        # This is the row that exhibits implicit rejection, and it is the one that could not be
        # built from ACVP at all, because ACVP's keyGen and encapsulation cases use disjoint
        # keys -- measured, the two ek sets do not intersect.
        other_dz = bytes([0x5A]) * 64
        other_ek, _ = vp.kem_keygen(other_dz)
        m = bytes([0x77]) * 32
        foreign_ct, senders_ss = vp.kem_encaps(other_ek, m)
        our_ss = vp.kem_decaps(ek_seed, foreign_ct)
        announced = vp.view_tag(senders_ss)
        derived = vp.view_tag(our_ss)
        v["V2-11"] = {
            "claim": "view-tag mismatch -> skip, and decapsulation does NOT fail",
            "given": {"our_kem_seed_dz": hx(ek_seed), "foreign_ek": hx(other_ek),
                      "foreign_ct": hx(foreign_ct),
                      "announced_view_tag": hx(announced)},
            "expect": {"decaps_raised": False,
                       "our_derived_ss": hx(our_ss),
                       "our_derived_view_tag": hx(derived),
                       "tags_differ": announced != derived,
                       "outcome": "not mine, no error"},
            "wrong": {"note": "an error, which per §2.5 aborts the whole scan and turns one "
                              "hostile announcement into permanent loss of every payment. "
                              "ML-KEM rejects IMPLICITLY: `our_derived_ss` above is a "
                              "well-formed pseudorandom secret, not a failure signal"}}
        assert senders_ss != our_ss, "implicit rejection should give a different secret"
    else:
        v["V2-11"] = {"claim": "view-tag mismatch -> skip",
                      "not_generatable": vp.KEM_ABSENT}
    v["V2-12"] = {"claim": "malformed ct -> skip at the entry point",
                  "given": {"ct_lengths": [1087, 0, 1089]},
                  "expect": {"outcome": "not mine, no error, three times"},
                  "wrong": {"note": "an error. Both references are layered so the entry point "
                                    "converts it; an implementation exposing the inner "
                                    "routine as its scanning API inherits the wrong "
                                    "behaviour"}}
    if vp.have_kem():
        # The end-to-end row: a sender encapsulates to our ek, and the stealth SECRET the
        # recipient derives is checked to control the address the sender published. Nothing
        # else in the suite closes that loop, and it is the one an implementer most wants.
        m13 = bytes([0x33]) * 32
        ct13, ss13 = vp.kem_encaps(ek, m13)
        ss13_r = vp.kem_decaps(ek_seed, ct13)
        _base, offset, _c = vp.h_of_ss(ss13)
        sk_int = int.from_bytes(spending_seed, "big")
        stealth_sk = (sk_int + offset) % vp.N
        stealth_pk_from_sk = vp.encode_compressed(vp.mul(stealth_sk))
        stealth_pk_from_pk = vp.encode_compressed(
            vp.add(vp.decode_compressed(spending_pk), vp.mul(offset)))
        addr13 = vp.address_of(vp.decode_compressed(stealth_pk_from_sk))
        v["V2-13"] = {
            "claim": "the derived key controls the derived address",
            "given": {"our_ek": hx(ek), "m": hx(m13), "ct": hx(ct13),
                      "spending_seed": hx(spending_seed)},
            "expect": {"sender_ss": hx(ss13), "recipient_ss": hx(ss13_r),
                       "secrets_agree": ss13 == ss13_r,
                       "offset": hx(offset.to_bytes(32, "big")),
                       "stealth_sk": hx(stealth_sk.to_bytes(32, "big")),
                       "stealth_pk_from_sender_side": hx(stealth_pk_from_pk),
                       "stealth_pk_from_recipient_secret": hx(stealth_pk_from_sk),
                       "the_two_agree": stealth_pk_from_pk == stealth_pk_from_sk,
                       "address": "0x" + hx(addr13),
                       "eip55": vp.eip55(addr13)},
            "wrong": {"unreduced_sum": "spending_sk + H(ss) taken without mod n, which differs "
                                       "only when the sum overflows the group order -- so it "
                                       "works until it silently does not",
                      "note": "deriving the address from `stealth_pk_from_pk` while spending "
                              "with a key derived differently. The two lines above MUST agree; "
                              "that agreement IS the claim"}}
        assert stealth_pk_from_pk == stealth_pk_from_sk, "sender and recipient disagree"
    else:
        v["V2-13"] = {"claim": "the derived key controls the derived address",
                      "not_generatable": vp.KEM_ABSENT}
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
                                    "metadata[1088]. This shape is byte-identical to a "
                                    "schemeId 5 first contact -- §6 declares the collision"}}
    v["V3-08a"] = {"claim": "the view tag is metadata[0..8]",
                   "given": {"metadata": hx(tag) + hx(ct)},
                   "expect": {"view_tag_at_index_0_8": hx(tag)},
                   "wrong": {"leading_eight_of_ct": hx(ct[:vp.VIEW_TAG_BYTES]),
                             "note": "a scanner that misses EVERY payment to it, silently, "
                                     "and reports a clean empty scan. At one byte it still "
                                     "matched 1 in 256 and left a symptom to chase"}}
    return v


# --------------------------------------------------------------------------------------
# §3 -- schemeId 4, the pairwise channel's base rung. Direct hash, no point on the wire.
# --------------------------------------------------------------------------------------

def group_3(t1: dict) -> dict[str, dict]:
    v: dict[str, dict] = {}
    kg = t1["keygen"][0]
    en = t1["encapsulation"][0]
    ek_seed = bytes.fromhex(kg["d"] + kg["z"])  # our (d, z) -- NIST-oracled with its ek
    ek = bytes.fromhex(kg["ek"])
    ct_acvp = bytes.fromhex(en["c"])            # a valid (ct, ss) pair, to a FOREIGN ek
    ss_pq = bytes.fromhex(en["k"])

    spending_seed = bytes([0x11]) * 32
    spending_pk = vp.encode_compressed(vp.mul(int.from_bytes(spending_seed, "big")))

    k4 = hashlib.sha3_256(DS_PAIRWISE_PQ + ss_pq).digest()
    v["V4-01"] = {
        "claim": "k_pairwise = SHA3-256 of the separator then ss_pq alone -- a direct hash, "
                 "full digest, nothing else bound in",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY,
        "given": {"domain_separator": DS_PAIRWISE_PQ.decode(), "ss_pq": hx(ss_pq),
                  "ss_pq_source": f"ACVP encapsulation tcId {en['tcId']}"},
        "expect": {"k_pairwise": hx(k4), "length": len(k4)},
        "wrong": {
            "ct_bound_in": hx(hashlib.sha3_256(DS_PAIRWISE_PQ + ss_pq + ct_acvp).digest()),
            "schemeId_5_separator": hx(hashlib.sha3_256(DS_PAIRWISE + ss_pq).digest()),
            "note": "binding ct in as well -- ML-KEM's FO transform already binds the "
                    "ciphertext into ss_pq, the property X-Wing relies on when it omits the "
                    "ciphertext from its own combiner; or the hybrid variant's separator, "
                    "which makes one rung's channel key derivable from the other's "
                    "derivation on the same secret",
        },
    }
    v["V4-02"] = {
        "claim": "the channel-key derivation differs from schemeId 5's on the same inputs "
                 "-- the two separators are distinct strings",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY,
        "given": {"ss_pq": hx(ss_pq),
                  "separator_schemeId_4": DS_PAIRWISE_PQ.decode(),
                  "separator_schemeId_5": DS_PAIRWISE.decode()},
        "expect": {"under_schemeId_4": hx(k4),
                   "under_schemeId_5_separator":
                       hx(hashlib.sha3_256(DS_PAIRWISE + ss_pq).digest()),
                   "assertion": "different"},
        "wrong": {"note": "the same key. The domain separation this row pins is the whole "
                          "reason both strings are stated: a schemeId 4 channel key, a "
                          "schemeId 5 channel key and a schemeId 3 payment secret MUST NOT "
                          "be derivable from one another"},
    }

    if vp.have_kem():
        # A REAL first contact, end to end: encapsulated to our ek, decapsulated with our
        # (d, z), the channel admitted by its own tag, and the payment at counter 0 spendable.
        # ACVP cannot supply this -- its keyGen and encapsulation cases use disjoint keys --
        # which is the same boundary V2-11 and V2-13 sit on.
        encap_seed = bytes([0x77]) * 32  # §3.3: the announce seed is 32 B, encap_seed alone
        ct4, ss4 = vp.kem_encaps(ek, encap_seed)
        k = hashlib.sha3_256(DS_PAIRWISE_PQ + ss4).digest()
        ss_0 = pairwise_ss(k, 0)
        tag0 = vp.view_tag(ss_0)
        v["V4-03"] = {
            "claim": "first contact is empty ephemeralPubKey, view_tag || ct in metadata",
            "given": {"our_ek": hx(ek), "encap_seed": hx(encap_seed), "ct": hx(ct4)},
            "expect": {"ss_pq": hx(ss4), "k_pairwise": hx(k),
                       "ss_at_counter_0": hx(ss_0), "view_tag": hx(tag0),
                       "ephemeralPubKey": "", "ephemeralPubKey_bytes": 0,
                       "metadata": hx(tag0) + hx(ct4),
                       "metadata_bytes": len(tag0) + len(ct4),
                       "payload_bytes": len(tag0) + len(ct4)},
            "wrong": {"ct_in_ephemeralPubKey": {"ephemeralPubKey": hx(ct4),
                                                "metadata": hx(tag0)},
                      "ct_alone_no_tag": hx(ct4),
                      "note": "schemeId 2's field convention, which no length check "
                              "distinguishes; or ct with no tag, the shape a port of the "
                              "upstream reference produces -- a first contact that is not "
                              "self-validating, so every retention rule downstream gates on "
                              "nothing"},
        }

        # Ours admits; a stranger's is discarded with nothing retained. The stranger's
        # branch is the one implicit rejection makes dangerous: decapsulation yields a
        # well-formed candidate key and NO error, so the tag is the only evidence there is.
        our_ss = vp.kem_decaps(ek_seed, ct4)
        our_k = hashlib.sha3_256(DS_PAIRWISE_PQ + our_ss).digest()
        our_tag = vp.view_tag(pairwise_ss(our_k, 0))
        other_ek, _ = vp.kem_keygen(bytes([0x5A]) * 64)
        foreign_ct, senders_ss = vp.kem_encaps(other_ek, bytes([0x88]) * 32)
        sender_k = hashlib.sha3_256(DS_PAIRWISE_PQ + senders_ss).digest()
        foreign_announced = vp.view_tag(pairwise_ss(sender_k, 0))
        ss_f = vp.kem_decaps(ek_seed, foreign_ct)
        k_f = hashlib.sha3_256(DS_PAIRWISE_PQ + ss_f).digest()
        tag_f = vp.view_tag(pairwise_ss(k_f, 0))
        v["V4-03a"] = {
            "claim": "the first contact's own view tag verifies at counter 0, and that is "
                     "what admits the channel",
            "given": {"our_tracking_key_dz": hx(ek_seed),
                      "ours": {"metadata": hx(tag0) + hx(ct4)},
                      "strangers": {"metadata": hx(foreign_announced) + hx(foreign_ct)}},
            "expect": {"ours": {"derived_ss_pq": hx(our_ss),
                                "derived_view_tag": hx(our_tag),
                                "tags_match": our_tag == tag0,
                                "outcome": "admitted -- and it is also a payment, V4-03b"},
                       "strangers": {"decaps_raised": False,
                                     "derived_ss_pq": hx(ss_f),
                                     "derived_view_tag": hx(tag_f),
                                     "tags_match": foreign_announced == tag_f,
                                     "outcome": "discarded with nothing retained"}},
            "wrong": {"note": "admitting on decapsulation alone, which retains one channel "
                              "per first contact ever seen -- a candidate channel key is "
                              "not by itself evidence of anything; or deriving the tag at "
                              "counter 1, which matches nothing"},
        }
        assert our_ss == ss4, "recipient decapsulation disagrees with the sender"
        assert our_tag == tag0, "the recipient must re-derive the announced tag"
        assert foreign_announced != tag_f, "implicit rejection should mismatch the tag"

        _b0, off0, _c0 = vp.h_of_ss(ss_0)
        sk_int = int.from_bytes(spending_seed, "big")
        stealth_sk = (sk_int + off0) % vp.N
        from_sk = vp.encode_compressed(vp.mul(stealth_sk))
        from_pk = vp.encode_compressed(
            vp.add(vp.decode_compressed(spending_pk), vp.mul(off0)))
        addr = vp.address_of(vp.decode_compressed(from_sk))
        v["V4-03b"] = {
            "claim": "the admitted first contact is also a payment, at counter 0",
            "given": {"spending_seed": hx(spending_seed), "k_pairwise": hx(k),
                      "counter": 0},
            "expect": {"ss": hx(ss_0), "offset": hx(off0.to_bytes(32, "big")),
                       "stealth_sk": hx(stealth_sk.to_bytes(32, "big")),
                       "stealth_pk_from_recipient_secret": hx(from_sk),
                       "stealth_pk_from_sender_side": hx(from_pk),
                       "the_two_agree": from_sk == from_pk,
                       "address": "0x" + hx(addr), "eip55": vp.eip55(addr)},
            "wrong": {"note": "admitting the channel and deriving no payment -- the first "
                              "payment on every channel, lost systematically with no "
                              "error"},
        }
        assert from_sk == from_pk, "sender and recipient disagree on the stealth key"
    else:
        for rid, claim in (("V4-03", "first contact is empty ephemeralPubKey, view_tag || "
                                     "ct in metadata"),
                           ("V4-03a", "the first contact's own view tag verifies at counter "
                                      "0, and that is what admits the channel"),
                           ("V4-03b", "the admitted first contact is also a payment, at "
                                      "counter 0")):
            v[rid] = {"claim": claim, "not_generatable": vp.KEM_ABSENT}

    meta4 = spending_pk + ek
    v["V4-04"] = {
        "claim": "meta-address is 1217 B with ONE point",
        "given": {"spending_pk": hx(spending_pk), "ek": hx(ek),
                  "ek_source": f"ACVP keyGen tcId {kg['tcId']}",
                  "wrong_length_example": 1250},
        "expect": {"meta_address": hx(meta4), "length": len(meta4),
                   "outcome_at_1250": "error at decode"},
        "wrong": {"note": "validating two points, ported from schemeId 5's decoder -- bytes "
                          "33..66 of this meta-address are ML-KEM key material, not a curve "
                          "point"},
    }
    seed96 = spending_seed + ek_seed
    v["V4-06"] = {
        "claim": "keygen seed is 96 B, and the delegated object is kem_seed alone",
        "given": {"keygen_seed": hx(seed96), "split": "spending_seed(32) || kem_seed(64)",
                  "kem_seed_source": f"ACVP keyGen tcId {kg['tcId']}",
                  "wrong_length_example": 128},
        "expect": {"spending_pk": hx(spending_pk), "ek": hx(ek),
                   "tracking_key_is_the_dz_seed": hx(ek_seed),
                   "outcome_at_128": "error at keygen",
                   "delegation_scan": "the 33 window offsets of the 64-byte kem_seed, "
                                      "already complete -- the 65-offset scan over a "
                                      "96-byte delegated object belongs to schemeId 5, "
                                      "which delegates two secrets"},
        "wrong": {"note": "accepting schemeId 5's 128-byte seed"},
    }
    # V4-07 plants the spending seed inside the delegated kem_seed. Without a committed
    # planted-offset row, a port that omits §2.1's scan passes every other schemeId 4 row
    # while placing the spending seed verbatim in delegated scanner material; V3-02 and
    # V5-01 witness only the 65-offset two-secret form, in files a scheme-4-only port
    # never loads. Offsets: the window's two ends plus one interior; the clean seed is
    # the positive control, on V5-01's pattern.
    offsets4 = [0, 16, 32]
    planted4 = {}
    for off in offsets4:
        buf = bytearray(bytes([0x44]) * 64)
        buf[off:off + 32] = spending_seed
        planted4[off] = hx(bytes(buf))
    v["V4-07"] = {
        "claim": "keygen scans the 64-byte kem_seed for the spending_seed at all 33 "
                 "offsets and refuses the coincidence",
        "given": {"spending_seed": hx(spending_seed),
                  "kem_seeds_by_offset": planted4,
                  "offsets": "0 and 32 are the 33-offset window's two ends; 16 is interior",
                  "kem_seed_with_no_coincidence": hx(bytes([0x44]) * 64)},
        "expect": {"outcome_planted": "error at keygen, all three",
                   "outcome_clean": "outputs, no error"},
        "wrong": {"note": "omitting the scan -- no other committed schemeId 4 row reaches "
                          "it, so a port that skips it passes this file while handing the "
                          "spending seed to a scanning service"},
    }
    return v


# --------------------------------------------------------------------------------------
# §3.12 -- schemeId 5, the hybrid channel variant. The delta rows: EC half plus combiner.
# --------------------------------------------------------------------------------------

def group_3_12(t1: dict) -> dict[str, dict]:
    v: dict[str, dict] = {}
    en = t1["encapsulation"][0]
    ek = bytes.fromhex(en["ek"])
    ct = bytes.fromhex(en["c"])
    ss_pq = bytes.fromhex(en["k"])

    spending_seed = bytes([0x11]) * 32
    spending_pk = vp.encode_compressed(vp.mul(int.from_bytes(spending_seed, "big")))
    esk = int.from_bytes(bytes([0x22]) * 32, "big")
    epk = vp.encode_compressed(vp.mul(esk))
    v_seed = int.from_bytes(bytes([0x33]) * 32, "big")
    viewing_pk_ec = vp.encode_compressed(vp.mul(v_seed))
    shared_pt = vp.mul(esk, vp.decode_compressed(viewing_pk_ec))
    ss_ec = shared_pt[0].to_bytes(32, "big")

    ikm = ss_ec + ss_pq + epk + ct + viewing_pk_ec + ek
    k5 = hashlib.sha3_256(DS_PAIRWISE + ikm).digest()
    ss_0 = pairwise_ss(k5, 0)
    tag_0 = vp.view_tag(ss_0)
    ss_1 = pairwise_ss(k5, 1)
    tag_1 = vp.view_tag(ss_1)

    offsets = [0, 40, 47, 5, 16, 20]
    planted = {}
    for off in offsets:
        buf = bytearray(bytes([0x44]) * 96)
        buf[off:off + 32] = spending_seed
        planted[off] = hx(bytes(buf))
    v["V5-01"] = {
        "claim": "keygen seed is 128 B, and the spending_seed scan covers the whole 96-byte "
                 "delegated object at all 65 offsets",
        "given": {"lengths": [128, 96, 127],
                  "spending_seed": hx(spending_seed),
                  "delegated_objects_by_offset": planted,
                  "offsets_wholly_inside_a_half": [0, 40, 47],
                  "offsets_straddling_the_boundary": [5, 16, 20],
                  "delegated_with_no_coincidence": hx(bytes([0x44]) * 96)},
        "expect": {"outcome_lengths": "outputs at 128, errors at 96 and 127",
                   "outcome_planted": "error at keygen, all six",
                   "outcome_clean": "outputs, no error"},
        "wrong": {"note": "accepting schemeId 4's 96-byte seed; or scanning the two halves "
                          "separately, which covers 34 of the 65 offsets and accepts the "
                          "straddling cases -- placing the spending seed verbatim in bytes "
                          "handed to a scanning service"},
    }
    v["V5-02"] = {
        "claim": "the channel key is the hybrid combiner's output: separator first, "
                 "six-field IKM, full digest",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY,
        "given": {"domain_separator": DS_PAIRWISE.decode(),
                  "parts": {"ss_ec": hx(ss_ec), "ss_pq": hx(ss_pq), "epk": hx(epk),
                            "ct": hx(ct), "viewing_pk_ec": hx(viewing_pk_ec),
                            "ek": hx(ek)}},
        "expect": {"k_pairwise": hx(k5)},
        "wrong": {
            "three_field_form":
                hx(hashlib.sha3_256(DS_PAIRWISE + ss_ec + ss_pq + epk).digest()),
            "appended_separator": hx(hashlib.sha3_256(ikm + DS_PAIRWISE).digest()),
            "schemeId_3_separator": hx(hashlib.sha3_256(DS_HYBRID + ikm).digest()),
            "note": "the three-field IKM, which the upstream references derive and which "
                    "drops the identity binding; the separator appended rather than first; "
                    "or the per-payment hybrid separator, which makes a channel key "
                    "derivable from a schemeId 3 derivation on the same inputs",
        },
    }
    flipped = bytes([epk[0] ^ 0x01]) + epk[1:]
    k5_flipped = hashlib.sha3_256(
        DS_PAIRWISE + ss_ec + ss_pq + flipped + ct + viewing_pk_ec + ek).digest()
    v["V5-03"] = {
        "claim": "epk is bound into the channel KDF",
        "given": {"epk": hx(epk), "epk_parity_flipped": hx(flipped)},
        "expect": {"k_a": hx(k5), "k_b": hx(k5_flipped), "assertion": "different"},
        "wrong": {"note": "the same key -- the flipped point has the same x-coordinate, so "
                          "without epk in the IKM this is a replay with a "
                          "different-looking announcement"},
    }
    v["V5-04"] = {
        "claim": "the counter is NONCE_BYTES-byte big-endian in the derivation, appears on "
                 "no wire, and a memo starts at counter 1",
        "given": {"k_pairwise": hx(k5), "counter": 1, "nonce_bytes": NONCE_BYTES,
                  "nonce": hx(ube_nonce(1))},
        "expect": {"ss": hx(ss_1), "view_tag": hx(tag_1),
                   "memo_metadata": hx(tag_1), "memo_bytes": len(tag_1)},
        "wrong": {
            "eight_byte_counter": hx(hashlib.sha256(
                DS_PAIRWISE_PAYMENT + k5 + (1).to_bytes(8, "big")).digest()),
            "little_endian_counter": hx(hashlib.sha256(
                DS_PAIRWISE_PAYMENT + k5 + (1).to_bytes(NONCE_BYTES, "little")).digest()),
            "memo_at_counter_0": hx(tag_0),
            "note": "a different width or endianness gives a different ss silently, from "
                    "the same channel key and the same counter; publishing the counter puts "
                    "a field on the wire that is not one; and a memo at counter 0 "
                    "re-derives the first contact's address, linking the two on chain",
        },
    }
    v["V5-05a"] = {
        "claim": "ss = SHA256 of the payment separator, the channel key and the nonce, and "
                 "the view tag follows from ss",
        "provisional": True,
        "provisional_because": PROVISIONAL_WHY,
        "given": {"domain_separator": DS_PAIRWISE_PAYMENT.decode(), "k_pairwise": hx(k5),
                  "counters": [0, 1]},
        "expect": {"ss_counter_0": hx(ss_0), "view_tag_counter_0": hx(tag_0),
                   "ss_counter_1": hx(ss_1), "view_tag_counter_1": hx(tag_1),
                   "assertion": "two payment secrets, two view tags, all four distinct"},
        "wrong": {
            "tag_from_key_and_nonce_directly": hx(hashlib.sha256(
                vp.DS_VIEWTAG + k5 + ube_nonce(1)).digest()[:vp.VIEW_TAG_BYTES]),
            "note": "deriving the tag from the channel key and nonce without ss in between "
                    "-- a well-formed eight-byte value that no conforming sender emits, so "
                    "a scanner using it matches nothing",
        },
    }
    v["V5-06"] = {
        "claim": "the memo is view_tag(8) and nothing else",
        "given": {"view_tag": hx(tag_1)},
        "expect": {"metadata": hx(tag_1), "metadata_bytes": vp.VIEW_TAG_BYTES,
                   "ephemeralPubKey_bytes": 0,
                   "round_trip": "parses back to the same eight bytes"},
        "wrong": {"with_trailing_counter": hx(tag_1 + ube_nonce(1)),
                  "one_byte_tag": hx(tag_1[:1]),
                  "note": "24 bytes with a trailing counter, or 25 with a second eight-byte "
                          "confirmation field as well -- shapes the upstream references "
                          "emit; or a one-byte tag, whose matches are spurious at 1 in 256 "
                          "and which cannot terminate recovery"},
    }
    v["V5-07"] = {
        "claim": "first contact is epk in ephemeralPubKey, view_tag || ct in metadata",
        "given": {"epk": hx(epk), "view_tag_at_counter_0": hx(tag_0), "ct": hx(ct)},
        "expect": {"ephemeralPubKey": hx(epk),
                   "metadata": hx(tag_0) + hx(ct),
                   "metadata_bytes": vp.VIEW_TAG_BYTES + len(ct),
                   "payload_bytes": len(epk) + vp.VIEW_TAG_BYTES + len(ct)},
        "wrong": {"swapped_fields": {"ephemeralPubKey": hx(tag_0) + hx(ct),
                                     "metadata": hx(epk)},
                  "ct_alone_no_tag": hx(ct),
                  "note": "the fields swapped; or ct with no tag, the shape a port of the "
                          "upstream reference produces. This shape is byte-identical to a "
                          "schemeId 3 announcement -- recognition is by schemeId plus the "
                          "field lengths, and the schemeId is on the wire"},
    }
    v["V5-09"] = {
        "claim": "a bad epk is a skip, not an error",
        "given": {"epk_zero": hx(bytes(33)),
                  "epk_not_a_point": hx(b"\x02" + b"\xff" * 32),
                  "epk_compact_0x05": hx(b"\x05" + viewing_pk_ec[1:])},
        "expect": {"outcome": "not mine, three times, no error"},
        "wrong": {"note": "an error, which aborts the scan -- a permanent halt any stranger "
                          "can trigger for one announcement's gas. One upstream reference "
                          "accepts the 0x05 tag and stores the channel; the other refuses "
                          "it"},
    }
    v["V5-10"] = {
        "claim": "a ct of the wrong length is a skip",
        "given": {"ct_length": 1087},
        "expect": {"outcome": "not mine, no error"},
        "wrong": {"note": "an error"},
    }
    _b0, off0, _c0 = vp.h_of_ss(ss_0)
    addr = vp.address_of(vp.add(vp.decode_compressed(spending_pk), vp.mul(off0)))
    v["V5-11"] = {
        "claim": "an address comparison is on the 20 address bytes, never on a string form",
        "given": {"address_lowercase": "0x" + hx(addr), "address_eip55": vp.eip55(addr)},
        "expect": {"assertion": "the two forms name the same 20 bytes and MUST compare "
                                "equal"},
        "wrong": {"note": "string comparison across the two forms, which matches nothing, "
                          "silently"},
    }
    corrupted = bytes([tag_0[0] ^ 0xFF]) + tag_0[1:]
    v["V5-12"] = {
        "claim": "a channel MUST NOT be retained without a view-tag match on the first "
                 "contact itself",
        "given": {"metadata": hx(corrupted) + hx(ct),
                  "derivable_view_tag_at_counter_0": hx(tag_0)},
        "expect": {"tags_match": False,
                   "outcome": "not retained, nothing stored, no error"},
        "wrong": {"note": "retained on decapsulation alone -- implicit rejection means "
                          "decapsulation always yields a well-formed candidate key, so that "
                          "rule retains one channel per first contact ever seen; or gating "
                          "on a paired memo's tag, a field that is not on the wire"},
    }
    v["V5-13"] = {
        "claim": "a duplicate channel key MUST NOT be retained twice",
        "given": {"first_contact": "the announcement of V5-07, replayed byte-identically"},
        "expect": {"retained_channels": 1,
                   "replay_outcome": "skip, and present no payment"},
        "wrong": {"note": "two, and the list grows without bound even with the gate in "
                          "place -- a replay is free for the replayer; or one channel "
                          "retained but the replay credited as a second payment, which "
                          "the retention count alone does not catch"},
    }
    v["V5-15"] = {
        "claim": "a scanning context cannot hold a sender-side channel",
        "given": {"attempt": "place a channel the caller opened as payer into a scanning "
                             "context"},
        "expect": {"outcome": "rejected by construction -- it does not compile, or the API "
                              "offers no such call"},
        "wrong": {"note": "accepted and filtered at match time, which a refactor breaks "
                          "with no test failing; the failure reports a counterparty's funds "
                          "as the user's own"},
    }
    v["V5-16"] = {
        "claim": "a schemeId mismatch is a skip",
        "given": {"announcements": [{"schemeId": 2}, {"schemeId": 4}],
                  "recipient_registered_under": 5},
        "expect": {"outcome": "not mine, twice, no error"},
        "wrong": {"note": "an error -- a permanent scan abort any stranger can trigger for "
                          "one announcement's gas"},
    }
    tag_4 = vp.view_tag(pairwise_ss(k5, 4))
    tag_5 = vp.view_tag(pairwise_ss(k5, 5))
    tag_out = vp.view_tag(pairwise_ss(k5, 4 + SCAN_LOOKAHEAD))
    v["V5-06a"] = {
        "claim": "a scanner matches a memo by deriving the next SCAN_LOOKAHEAD counters, "
                 "not by reading one",
        "provisional": True,
        "provisional_because": SCAN_LOOKAHEAD_WHY,
        "given": {"k_pairwise": hx(k5), "highest_matched_counter": 3,
                  "scan_lookahead": SCAN_LOOKAHEAD,
                  "window": f"counters 4 through {3 + SCAN_LOOKAHEAD} inclusive",
                  "memos": {"counter_4": hx(tag_4), "counter_5": hx(tag_5),
                            f"counter_{4 + SCAN_LOOKAHEAD}": hx(tag_out)}},
        "expect": {"counter_4": "matched", "counter_5": "matched",
                   f"counter_{4 + SCAN_LOOKAHEAD}": "NOT matched, and no error",
                   "window_is_a_lookup": "the tags for the window are derived once and a "
                                         "memo costs one comparison, not a search"},
        "wrong": {"note": "matching the out-of-window memo, which means the window is not "
                          "applied and the scan is unbounded in the counter; or failing on "
                          "it, which turns a sender's skip into an error a stranger could "
                          "also cause"},
    }
    # The matched row's identity is its ANNOUNCED address, echoed through the report -- the
    # watcher treats it as OPAQUE (it enters no derivation, and verifying it needs the
    # spending point a delegation MUST NOT include), so the fixture's value is an arbitrary
    # constant, deliberately not a derived one.
    row_identity = "99" * 20
    v["V5-21"] = {
        "claim": "a watch delegation carries one channel's key and counter position and "
                 "nothing else -- never the tracking key, never the spending point -- and "
                 "its report is the matched counter AND the matched row's identity",
        "given": {"watch": {"k_pairwise": hx(k5), "next_counter": 4},
                  "memo": hx(tag_4),
                  "memo_row_identity": row_identity},
        "expect": {"matched_counter": 4,
                   "report_row_identity": row_identity,
                   "report": "the matched counter and the identity of the matched log row "
                             "-- its ANNOUNCED address, echoed opaquely so the recipient "
                             "knows which public row to retrieve; the watch type has no "
                             "field for a DERIVED address or a key it must not hold, and "
                             "the recipient performs the derived-address comparison locally"},
        "wrong": {"note": "including the tracking key, which un-scopes the delegation back "
                          "to the whole graph; or the spending point, which names the "
                          "recipient in their registry entry; or a report without the row "
                          "identity, which says a counter matched but not which public row "
                          "to retrieve and verify"},
    }
    v["V5-20"] = {
        "claim": "a scanner that stops deriving for a confirmed channel can resume it "
                 "without the seed-only path",
        "given": {"retained": {"k_pairwise": hx(k5), "highest_matched_counter": 3,
                               "first_contact_location": "retained with the channel"},
                  "then": "idle past the scanner's own CHANNEL_IDLE_SCAN, then a memo",
                  "memo": hx(tag_4)},
        "expect": {"outcome": "the memo matches at counter 4 from the retained state, and "
                              "the payment is found by rescanning ONE known channel"},
        "wrong": {"note": "resumption only through the whole-chain recovery path, whose "
                          "cost is first-contacts times memos; or no resumption at all, "
                          "which shows the user a live channel that is not being derived"},
    }
    return v


BUILDERS = {"1": lambda t1: group_1(), "5": lambda t1: group_5(),
            "2": group_2, "2.9": group_2_9, "3": group_3, "3.12": group_3_12,
            "4": lambda t1: group_4()}


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
