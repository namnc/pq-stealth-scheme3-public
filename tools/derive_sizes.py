#!/usr/bin/env python3
"""Re-derive this document's byte figures from FIPS 203 and from §5's wire rules.

**What it covers, and what it does not.** It checks the figures listed in its own tables:
the announcement payloads and their field splits, the meta-addresses, the registration
ratios, and the delegation window counts. **It does not scan the documents for figures it
has not been told about** -- so a new byte figure is unchecked until someone adds it here,
and the closing line says so rather than claiming "every quoted figure"; that claim over
partial coverage would be an overclaimed figure inside the harness built to remove
overclaimed figures.

**Why this file exists.** Rule #54 of this project's method is that a figure in a document
must have a committed harness -- a number whose generator no longer exists is
unfalsifiable, which is worse than an absent number. `harness/announcement/measure.py`
reads its field lengths from here rather than retyping them, because a retyped copy of a
wire table can carry a superseded view-tag width while looking complete.

**This derivation is deliberately independent of the code that produced the numbers.** It
computes `ek` from FIPS 203's formula rather than from the constant 1 184, then asserts
agreement with it. Re-deriving from the constant that produced a figure proves only that
copying worked.

Run: `python3 tools/derive_sizes.py`   Exit 0 if every figure agrees, 1 otherwise.
"""

from __future__ import annotations

import sys

# ---- FIPS 203 (ML-KEM-768) -----------------------------------------------------------
MLKEM_768_K = 3
MLKEM_768_DU = 10
MLKEM_768_DV = 4
EK = 384 * MLKEM_768_K + 32
CT = 32 * (MLKEM_768_DU * MLKEM_768_K + MLKEM_768_DV)
DK_EXPANDED = 768 * MLKEM_768_K + 96      # not used on the wire; see the seed note below
CT_MLKEM768 = CT

# FIPS 203's own stated lengths for ML-KEM-768, asserted against the formulas above. If the
# two ever disagree, one of them is wrong and the failure should be loud.
FIPS_203_EK = 1_184
FIPS_203_CT = 1_088

# ---- §5's wire rules -----------------------------------------------------------------
SEC1_COMPRESSED = 33      # secp256k1 point, SEC1 compressed, per §1
VIEW_TAG = 1              # §5 rule 1: the FIRST BYTE of `metadata`, in EVERY announcement.
                          # One, everywhere; there is no confirm tag. It was eight until the
                          # announced `stealthAddress` was made the authoritative check
                          # (§2.4 MUST) and the tag was narrowed to a prefilter.
SCALAR = 32               # a secp256k1 scalar, or a 32-byte seed
SPENDING_PK = 33          # secp256k1, SEC1 compressed
VIEWING_PK_EC = 33

# Each is stated as its construction so that a change to one field cannot leave a total
# behind.
ANNOUNCE_ERC = {
    "schemeId 3 announcement":  (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122),
}

# §5's shape is the PAIR of field lengths, not the total, and the distinction is
# load-bearing: two rungs can share a total and still be distinguishable, because one puts
# `ct` in `ephemeralPubKey` and the other in `metadata`. Modelling the total alone would
# call that a collision.
#
# (`ephemeralPubKey`, `metadata`) per row.
SHAPES = {
    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),
}

# The `schemeId` each shape belongs to, so the gas harness can address them. Stated here
# rather than parsed out of the key: a name is prose and an id is a wire field, and the
# ERC-5564 registry is a namespace where getting one wrong publishes material under another
# scheme.
SHAPE_SCHEME_ID = {
    "schemeId 3 announcement": 3,
}

# Pairs this tree declares indistinguishable by length. Asserted rather than left as a
# coincidence, and any UNDECLARED pair sharing a shape is a failure -- recognition is by
# `schemeId` plus the field lengths, so a collision is not a conformance defect, but one
# that appeared without anyone writing it down would mean §5's recognition rule had gone
# stale. Empty here, and the detector below is what keeps it honest.
DECLARED_SHAPE_COLLISIONS: list[tuple[str, str]] = []

# The delegation window scans. Both were the subject of a security fix: the scan is over the
# WHOLE delegated object, so the count is (len - 32 + 1) and not (len / 32).
DELEGATION = {
    "schemeId 3 (viewing_ec(32) || kem_seed(64) = 96 B)": (96 - SCALAR + 1, 65),
}

META = {
    "schemeId 3": (SPENDING_PK + VIEWING_PK_EC + EK,   1_250),
}

# §6's registration table. `schemeId 1`'s 66 B is ERC-5564's own meta-address -- two
# SEC1-compressed points -- and is the baseline every ratio in that column is against. The
# ratios are checked here rather than trusted because they are the only figures in that
# table nobody measured OR quoted from elsewhere: they were computed while writing it, which
# is exactly the case rule #54 covers.
META_CLASSICAL = 2 * SPENDING_PK          # ERC-5564 schemeId 1: spending || viewing
REGISTRATION_RATIOS = {
    "1": (META_CLASSICAL, "1.0"),
    "3": (1_250, "18.9"),
}


def main() -> int:
    bad: list[str] = []

    print("ML-KEM-768 lengths, from FIPS 203's formulas")
    print(f"  ek = 384*{MLKEM_768_K} + 32          = {EK} B   (FIPS 203: {FIPS_203_EK})")
    print(f"  ct = 32*({MLKEM_768_DU}*{MLKEM_768_K} + {MLKEM_768_DV})          "
          f"= {CT} B   (FIPS 203: {FIPS_203_CT})")
    if EK != FIPS_203_EK:
        bad.append(f"ek {EK} != FIPS 203's {FIPS_203_EK}")
    if CT != FIPS_203_CT:
        bad.append(f"ct {CT} != FIPS 203's {FIPS_203_CT}")

    print("\nthe announcement payloads, from the same primitives")
    for name, (derived, quoted) in ANNOUNCE_ERC.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<28}{derived:>6} B   spec {quoted:>6}   {mark}")
        if derived != quoted:
            bad.append(f"{name}: derived {derived} != quoted {quoted}")

    print("\nshapes are (ephemeralPubKey, metadata) -- the pair, which is what §5 "
          "recognises on")
    for name, (epk_len, md_len) in SHAPES.items():
        total = epk_len + md_len
        quoted = ANNOUNCE_ERC[name][1]
        mark = "ok" if total == quoted else "MISMATCH"
        print(f"  {name:<38}({epk_len:>4}, {md_len:>5})  = {total:>5} B   "
              f"spec {quoted:>5}   {mark}")
        if total != quoted:
            bad.append(f"{name}: shape ({epk_len}, {md_len}) totals {total} != §5's {quoted}")

    by_shape: dict[tuple[int, int], list[str]] = {}
    for name, shape in SHAPES.items():
        by_shape.setdefault(shape, []).append(name)
    declared = {frozenset(pair) for pair in DECLARED_SHAPE_COLLISIONS}
    for shape, names in sorted(by_shape.items()):
        if len(names) < 2:
            continue
        if frozenset(names) in declared:
            print(f"  declared collision at {shape}: {' == '.join(sorted(names))}   ok")
        else:
            bad.append(f"UNDECLARED shape collision at {shape}: {', '.join(sorted(names))} -- "
                       f"record it in §5 and in DECLARED_SHAPE_COLLISIONS, or separate them")
    for pair in DECLARED_SHAPE_COLLISIONS:
        if SHAPES[pair[0]] != SHAPES[pair[1]]:
            bad.append(f"§5 declares {pair[0]} and {pair[1]} the same shape and they are "
                       f"{SHAPES[pair[0]]} and {SHAPES[pair[1]]}")

    print("\ndelegation window counts -- (len - 32 + 1), not (len / 32)")
    for name, (derived, quoted) in DELEGATION.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {derived:>4} windows   spec {quoted:>4}   {mark}   {name}")
        if derived != quoted:
            bad.append(f"{name}: derived {derived} windows != quoted {quoted}")

    print("\nmeta-addresses, from §5's registry column")
    for name, (derived, quoted) in META.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<28}{derived:>6} B   spec {quoted:>6}   {mark}")
        if derived != quoted:
            bad.append(f"{name} meta-address: derived {derived} != quoted {quoted}")

    print(f"\nregistration calldata, per §6's table, against schemeId 1's "
          f"{META_CLASSICAL} B")
    for name, (size, quoted) in REGISTRATION_RATIOS.items():
        derived = f"{size / META_CLASSICAL:.1f}"
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  schemeId {name:<16}{size:>6} B   {derived:>6}x   spec {quoted:>6}x   {mark}")
        if derived != quoted:
            bad.append(f"schemeId {name} registration ratio: derived {derived} "
                       f"!= quoted {quoted}")

    # The tracking key is the SEED pair, not the expanded decapsulation key. Stated because
    # the difference is 64 bytes against 2 400 and the specification leans on it.
    print(f"\ntracking key is ML-KEM's (d, z) seed pair at 64 B, not the expanded "
          f"decapsulation key at {DK_EXPANDED} B")

    print()
    if bad:
        print(f"FAIL: {len(bad)} disagreement(s)")
        for b in bad:
            print("  " + b)
        return 1
    print("OK: every figure listed above re-derives from FIPS 203 and from §5's wire rules.\n"
          "    Coverage is what this file enumerates and no more -- it does NOT sweep the "
          "documents for\n    byte figures it has not been told about. A figure nobody adds "
          "here is a figure nobody checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
