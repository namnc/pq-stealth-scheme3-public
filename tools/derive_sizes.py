#!/usr/bin/env python3
"""Re-derive schemeId 6's meta-address and announcement sizes from first principles.

**What it covers, and what it does not.** It checks the figures listed in its own tables:
schemeId 6's meta-addresses and announcements at all three categories, schemeIds 2-5's
announcement payloads and meta-addresses, the memo, the one-time public key, and the two
delegation window counts. **It does not scan the documents for figures it has not been told
about** -- so a new byte figure is unchecked until someone adds it here, and the closing line
says so rather than claiming "every quoted figure" -- that claim over partial coverage
would be an overclaimed figure inside the harness built to remove overclaimed figures.

**Why this file exists.** §4.2 of the companion ERC quotes 4 128 / 5 600 / 7 072 bytes, and
rule #54 of this project's method is that a figure in a document must have a committed
harness — a number whose generator no longer exists is unfalsifiable, which is worse than an
absent number.

It also exists because the figures it replaced were wrong in a specific, instructive way.
§4.1 and §4.2 said the meta-address is `t1 ‖ ek`, 3 104 B at category 3. That omits `t0`.
`OPKGen` and `Track` form `t' = t + A·s1' + s2'` from the **full-precision** `t`, and
`t = t1·2^d + t0`; `t0`'s coefficients reach ±2^(d-1), which is enough to move the rounded
high bits. A sender holding `t1` alone therefore derives a different `t1_ot` than the
recipient's `Track` recomputes, and every payment lands at an address nobody can find.

**This derivation is deliberately independent of the code that produced the numbers.** It
computes the packing widths from FIPS 204's parameters rather than reading `spirit-poc`'s
`POLYT1_PACKEDBYTES` / `POLYT0_PACKEDBYTES`, and the KEM key length from FIPS 203's formula
rather than the constant 1 184 — then asserts agreement with both. Re-deriving from the
constant that produced a figure proves only that copying worked.

Run: `python3 tools/derive_sizes.py`   Exit 0 if every figure agrees, 1 otherwise.
"""

from __future__ import annotations

import sys

# ---- FIPS 204 (ML-DSA) ---------------------------------------------------------------
N = 256                  # polynomial degree
Q = 8_380_417            # modulus
D = 13                   # low-order bits of t dropped from the public key
Q_BITS = Q.bit_length()  # 23

# t1 holds the high bits: Q_BITS - D per coefficient. t0 holds D per coefficient.
T1_BITS_PER_COEFF = Q_BITS - D
T0_BITS_PER_COEFF = D
T1_BYTES_PER_POLY = N * T1_BITS_PER_COEFF // 8
T0_BYTES_PER_POLY = N * T0_BITS_PER_COEFF // 8

# `k` is the height of the public matrix, per ML-DSA category.
K_BY_CATEGORY = {2: 4, 3: 6, 5: 8}

# ---- FIPS 203 (ML-KEM-768) -----------------------------------------------------------
# This ladder injects ML-KEM-768 at EVERY category rather than pairing each ML-DSA category
# with the KEM of matching strength -- which is what `pq-stealth-addresses` does, and why
# `ek` and `ct` do not vary by category below.
MLKEM_768_K = 3
MLKEM_768_DU = 10
MLKEM_768_DV = 4
EK = 384 * MLKEM_768_K + 32
CT = 32 * (MLKEM_768_DU * MLKEM_768_K + MLKEM_768_DV)
DK_EXPANDED = 768 * MLKEM_768_K + 96      # not used on the wire; see the seed note below

# ---- the announcement ERC's own figures ----------------------------------------------
SEC1_COMPRESSED = 33      # secp256k1 point, SEC1 compressed, per §1
VIEW_TAG = 1              # §5 rule 1: the FIRST BYTE of `metadata`, in EVERY announcement.
                          # One, everywhere; there is no confirm tag. It was eight until the
                          # announced `stealthAddress` was made the authoritative check
                          # (§2.4 MUST) and the tag was narrowed to a prefilter.
# NONCE_BYTES is a parameter of §3.5's DERIVATION and is no longer a wire field. The counter is
# derived on both sides rather than transmitted -- so this constant
# still governs `ss = SHA256(DS || k_pairwise || ubeN(counter))` and contributes nothing to any
# payload below. It is kept here because a future revision that put a nonce back on the wire
# would need it, and because §3.5 quotes the width.
NONCE = 16                # §3.5's DERIVATION only. PROVISIONAL at 16 and raisable.
SCALAR = 32               # a secp256k1 scalar, or a 32-byte seed

# schemeIds 2 to 5, from §6's wire table. Each is stated as its construction so that a
# change to one field cannot leave a total behind.
T1_OT = {cat: k * T1_BYTES_PER_POLY for cat, k in K_BY_CATEGORY.items()}

ANNOUNCE_ERC = {
    "schemeId 2 announcement":  (CT + VIEW_TAG,                       1_089),
    "schemeId 3 announcement":  (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122),
    "schemeId 4 first contact": (VIEW_TAG + CT,                       1_089),
    "schemeId 5 first contact": (SEC1_COMPRESSED + VIEW_TAG + CT,     1_122),
    "memo (schemeIds 4, 5)":    (VIEW_TAG,                                 1),
    # schemeId 6's three, so the shape machinery below covers the WHOLE ladder
    # and `harness/announcement/measure.py` can read one table instead of retyping nine field
    # lengths. `t1_ot` is derived from FIPS 204's packing widths above, not from a constant.
    "schemeId 6 announcement, category 2": (T1_OT[2] + VIEW_TAG + CT, 2_369),
    "schemeId 6 announcement, category 3": (T1_OT[3] + VIEW_TAG + CT, 3_009),
    "schemeId 6 announcement, category 5": (T1_OT[5] + VIEW_TAG + CT, 3_649),
}

# §6's shape is the PAIR of field lengths, not the total, and the distinction is load-bearing:
# schemeId 2 and schemeId 4's first contact both total 1 089 B and are still distinguishable,
# because one puts `ct` in `ephemeralPubKey` and the other in `metadata`. Modelling the total
# alone would call that a collision.
#
# (`ephemeralPubKey`, `metadata`) per row of §6's table.
SHAPES = {
    "schemeId 2 announcement":  (CT,               VIEW_TAG),
    "schemeId 3 announcement":  (SEC1_COMPRESSED,  VIEW_TAG + CT),
    "schemeId 4 first contact": (0,                VIEW_TAG + CT),
    "schemeId 5 first contact": (SEC1_COMPRESSED,  VIEW_TAG + CT),
    "memo (schemeIds 4, 5)":    (0,                VIEW_TAG),
    "schemeId 6 announcement, category 2": (T1_OT[2], VIEW_TAG + CT),
    "schemeId 6 announcement, category 3": (T1_OT[3], VIEW_TAG + CT),
    "schemeId 6 announcement, category 5": (T1_OT[5], VIEW_TAG + CT),
}

# The `schemeId` each shape belongs to, so the gas harness can address them. Stated here rather
# than parsed out of the key: a name is prose and an id is a wire field, and the ERC-5564
# registry is a namespace where getting one wrong publishes material under another scheme.
SHAPE_SCHEME_ID = {
    "schemeId 2 announcement": 2,
    "schemeId 3 announcement": 3,
    "schemeId 4 first contact": 4,
    "schemeId 5 first contact": 5,
    "memo (schemeIds 4, 5)": 4,
    "schemeId 6 announcement, category 2": 6,
    "schemeId 6 announcement, category 3": 6,
    "schemeId 6 announcement, category 5": 6,
}

# The one pair §6 declares indistinguishable by length. Asserted rather than left as a
# coincidence, and any UNDECLARED pair sharing a shape is a failure -- recognition is by
# `schemeId` plus the field lengths, so a collision is not a conformance defect, but one that
# appeared without anyone writing it down would mean §6's note had gone stale.
DECLARED_SHAPE_COLLISIONS = [("schemeId 3 announcement", "schemeId 5 first contact")]

# The delegation window scans. Both were the subject of a security fix: the scan is over the
# WHOLE delegated object, so the count is (len - 32 + 1) and not (len / 32).
DELEGATION = {
    "schemeIds 3, 5 (viewing_ec(32) || kem_seed(64) = 96 B)": (96 - SCALAR + 1, 65),
    "schemeIds 2, 4, 6 (kem_seed(64) = 64 B)":                (64 - SCALAR + 1, 33),
}

# ---- what the reference implementation's own constants say ---------------------------
# Asserted, not used: if these ever disagree with the derivation above, one of the two is
# wrong and the failure should be loud.
SPIRIT_POC_POLYT1_PACKEDBYTES = 320
SPIRIT_POC_POLYT0_PACKEDBYTES = 416
SPIRIT_POC_EK_MLKEM768 = 1_184

# ---- the figures the specification quotes -------------------------------------------
# §4.2's meta-address table, and §4.3's announcement payloads.
SPEC_META = {2: 4_128, 3: 5_600, 5: 7_072}
SPEC_ANNOUNCEMENT = {2: 2_369, 3: 3_009, 5: 3_649}
CT_MLKEM768 = 1_088      # FIPS 203 ML-KEM-768 ciphertext
# NOT a second definition of the width. This shadowed the constant above, so two assignments
# governed one figure and changing the first alone would have moved the ladder's payloads and
# left schemeId 6's behind -- the propagation defect this file exists to catch, inside the
# file. One name.

# The WITHDRAWN meta-address figures — §4.2 declares the withdrawal — kept so the
# arithmetic of the defect they carry is reproducible rather than asserted: they are
# exactly the totals with `t0` omitted.
SUPERSEDED_META = {2: 2_464, 3: 3_104, 5: 3_744}

# schemeIds 2 to 5's meta-addresses, from §6's registry column -- without them this file
# would check only schemeId 6's figures, and its closing line would overclaim.
SPENDING_PK = 33          # secp256k1, SEC1 compressed
VIEWING_PK_EC = 33
META_2_TO_5 = {
    "schemeId 2": (SPENDING_PK + EK,                   1_217),
    "schemeId 3": (SPENDING_PK + VIEWING_PK_EC + EK,   1_250),
    "schemeId 4": (SPENDING_PK + EK,                   1_217),
    "schemeId 5": (SPENDING_PK + VIEWING_PK_EC + EK,   1_250),
}

# The one-time public key, which §4.6 quotes when pricing the address mapping. It is a full
# ML-DSA public key -- `rho` prepended to `t1_ot` -- and so is 32 bytes longer than the
# announcement field.
SEEDBYTES = 32
OPK_DS = {2: 1_312, 3: 1_952, 5: 2_592}

# §7's registration table. `schemeId 1`'s 66 B is
# ERC-5564's own meta-address -- two SEC1-compressed points -- and is the baseline every
# ratio in that column is against. The ratios are checked here rather than trusted because
# they are the only figures in that table nobody measured OR quoted from elsewhere: they
# were computed while writing it, which is exactly the case rule #54 covers.
META_CLASSICAL = 2 * SPENDING_PK          # ERC-5564 schemeId 1: spending || viewing
REGISTRATION_RATIOS = {
    "1": (META_CLASSICAL, "1.0"),
    "2": (1_217, "18.4"),
    "3": (1_250, "18.9"),
    "4": (1_217, "18.4"),
    "5": (1_250, "18.9"),
    "6, category 2": (4_128, "62.5"),
    "6, category 3": (5_600, "84.8"),
    "6, category 5": (7_072, "107.2"),
}

# The correction §7's registration table quotes as its reader's point: category 3's
# meta-address grew by this much when `t0` was found missing from the encoding.
T0_GROWTH_PCT = 80

# The PROSE ratio one line below that table. The plausible wrong value is
# 4.6x, which is 5 600 / 1 217 -- the ratio against schemeId 2 rather than against the
# largest of schemeIds 2 to 5, which is schemeId 3's and schemeId 5's 1 250. A figure computed
# while writing a sentence, one line under a table whose every figure this file checks.
LARGEST_2_TO_5 = 1_250
VS_LARGEST_2_TO_5 = "4.5"


def main() -> int:
    bad: list[str] = []
    print("packing widths, from FIPS 204 parameters")
    print(f"  t1: {T1_BITS_PER_COEFF} bits/coeff x {N} = {T1_BYTES_PER_POLY} B/poly")
    print(f"  t0: {T0_BITS_PER_COEFF} bits/coeff x {N} = {T0_BYTES_PER_POLY} B/poly")
    if T1_BYTES_PER_POLY != SPIRIT_POC_POLYT1_PACKEDBYTES:
        bad.append(f"t1 width {T1_BYTES_PER_POLY} != spirit-poc's "
                   f"{SPIRIT_POC_POLYT1_PACKEDBYTES}")
    if T0_BYTES_PER_POLY != SPIRIT_POC_POLYT0_PACKEDBYTES:
        bad.append(f"t0 width {T0_BYTES_PER_POLY} != spirit-poc's "
                   f"{SPIRIT_POC_POLYT0_PACKEDBYTES}")

    print(f"\nML-KEM-768 ek, from FIPS 203: 384*{MLKEM_768_K} + 32 = {EK} B")
    if EK != SPIRIT_POC_EK_MLKEM768:
        bad.append(f"ek {EK} != {SPIRIT_POC_EK_MLKEM768}")

    print("\nmeta-address = t1 || t0 || ek   (rho omitted per §4.2)")
    print(f"  {'cat':<5}{'k':>3}{'t1':>8}{'t0':>8}{'ek':>7}{'total':>9}{'spec':>9}")
    for cat, k in K_BY_CATEGORY.items():
        t1, t0 = k * T1_BYTES_PER_POLY, k * T0_BYTES_PER_POLY
        total = t1 + t0 + EK
        print(f"  {cat:<5}{k:>3}{t1:>8}{t0:>8}{EK:>7}{total:>9}{SPEC_META[cat]:>9}")
        if total != SPEC_META[cat]:
            bad.append(f"category {cat} meta-address {total} != §4.2's {SPEC_META[cat]}")

    print("\nannouncement = t1_ot || (view_tag || ct)")
    for cat, k in K_BY_CATEGORY.items():
        total = k * T1_BYTES_PER_POLY + VIEW_TAG + CT_MLKEM768
        if total != SPEC_ANNOUNCEMENT[cat]:
            bad.append(f"category {cat} announcement {total} != "
                       f"§4.3's {SPEC_ANNOUNCEMENT[cat]}")
        print(f"  category {cat}: {k * T1_BYTES_PER_POLY} + {VIEW_TAG} + {CT_MLKEM768} "
              f"= {total} B  (§4.3: {SPEC_ANNOUNCEMENT[cat]})")

    print("\nthe withdrawn figures are the t1-only totals, which is the defect itself")
    for cat, k in K_BY_CATEGORY.items():
        without_t0 = k * T1_BYTES_PER_POLY + EK
        mark = "==" if without_t0 == SUPERSEDED_META[cat] else "!="
        print(f"  category {cat}: t1 + ek = {without_t0} {mark} "
              f"{SUPERSEDED_META[cat]} (the t1-only reading of §4.2)")
        if without_t0 != SUPERSEDED_META[cat]:
            bad.append(f"category {cat}: withdrawn figure {SUPERSEDED_META[cat]} is not "
                       f"the t1-only total {without_t0}, so the account of the defect is "
                       f"wrong")

    print("\nthe announcement ERC's payloads, from the same primitives")
    for name, (derived, quoted) in ANNOUNCE_ERC.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<28}{derived:>6} B   spec {quoted:>6}   {mark}")
        if derived != quoted:
            bad.append(f"{name}: derived {derived} != quoted {quoted}")

    print("\nshapes are (ephemeralPubKey, metadata) -- the pair, which is what §6 recognises on")
    for name, (epk_len, md_len) in SHAPES.items():
        total = epk_len + md_len
        quoted = ANNOUNCE_ERC[name][1]
        mark = "ok" if total == quoted else "MISMATCH"
        print(f"  {name:<38}({epk_len:>4}, {md_len:>5})  = {total:>5} B   "
              f"spec {quoted:>5}   {mark}")
        if total != quoted:
            bad.append(f"{name}: shape ({epk_len}, {md_len}) totals {total} != §6's {quoted}")

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
                       f"record it in §6 and in DECLARED_SHAPE_COLLISIONS, or separate them")
    for pair in DECLARED_SHAPE_COLLISIONS:
        if SHAPES[pair[0]] != SHAPES[pair[1]]:
            bad.append(f"§6 declares {pair[0]} and {pair[1]} the same shape and they are "
                       f"{SHAPES[pair[0]]} and {SHAPES[pair[1]]}")

    print("\ndelegation window counts -- (len - 32 + 1), not (len / 32)")
    for name, (derived, quoted) in DELEGATION.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {derived:>4} windows   spec {quoted:>4}   {mark}   {name}")
        if derived != quoted:
            bad.append(f"{name}: derived {derived} windows != quoted {quoted}")

    print("\nschemeIds 2 to 5 meta-addresses, from §6's registry column")
    for name, (derived, quoted) in META_2_TO_5.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<28}{derived:>6} B   spec {quoted:>6}   {mark}")
        if derived != quoted:
            bad.append(f"{name} meta-address: derived {derived} != quoted {quoted}")

    print("\nthe one-time public key `opk_ds` = CRS_V1 || t1_ot, per §4.6")
    for cat, k in K_BY_CATEGORY.items():
        derived = SEEDBYTES + k * T1_BYTES_PER_POLY
        mark = "ok" if derived == OPK_DS[cat] else "MISMATCH"
        print(f"  category {cat}: 32 + {k * T1_BYTES_PER_POLY} = {derived} B   "
              f"spec {OPK_DS[cat]}   {mark}")
        if derived != OPK_DS[cat]:
            bad.append(f"category {cat} opk_ds: derived {derived} != quoted {OPK_DS[cat]}")

    print(f"\nregistration calldata, per §7's table, against schemeId 1's "
          f"{META_CLASSICAL} B")
    for name, (size, quoted) in REGISTRATION_RATIOS.items():
        derived = f"{size / META_CLASSICAL:.1f}"
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  schemeId {name:<16}{size:>6} B   {derived:>6}x   spec {quoted:>6}x   {mark}")
        if derived != quoted:
            bad.append(f"schemeId {name} registration ratio: derived {derived} "
                       f"!= quoted {quoted}")
    derived = f"{5_600 / LARGEST_2_TO_5:.1f}"
    mark = "ok" if derived == VS_LARGEST_2_TO_5 else "MISMATCH"
    print(f"  category 3 against the largest of schemeIds 2 to 5 ({LARGEST_2_TO_5} B): "
          f"{derived}x   spec {VS_LARGEST_2_TO_5}x   {mark}")
    if derived != VS_LARGEST_2_TO_5:
        bad.append(f"category 3 vs largest of 2-5: derived {derived} "
                   f"!= quoted {VS_LARGEST_2_TO_5}")
    if LARGEST_2_TO_5 != max(q for _d, q in META_2_TO_5.values()):
        bad.append(f"LARGEST_2_TO_5 is {LARGEST_2_TO_5}, but the largest meta-address in "
                   f"META_2_TO_5 is {max(q for _d, q in META_2_TO_5.values())}")

    growth = round(100 * (5_600 - SUPERSEDED_META[3]) / SUPERSEDED_META[3])
    mark = "ok" if growth == T0_GROWTH_PCT else "MISMATCH"
    print(f"  category 3 grew {SUPERSEDED_META[3]} -> 5600 B when `t0` was restored: "
          f"{growth}%   spec {T0_GROWTH_PCT}%   {mark}")
    if growth != T0_GROWTH_PCT:
        bad.append(f"t0 growth: derived {growth}% != quoted {T0_GROWTH_PCT}%")

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
    print("OK: every figure listed above re-derives from FIPS 204 and FIPS 203, and the "
          "reference implementation's constants agree.\n"
          "    Coverage is what this file enumerates and no more -- it does NOT sweep the "
          "documents for\n    byte figures it has not been told about. A figure nobody adds "
          "here is a figure nobody checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
