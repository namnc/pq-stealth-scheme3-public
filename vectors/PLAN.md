# Conformance vector plan — schemeId 3, and what it shares

## 1. What makes a vector explainable

Every vector is a JSON object with six fields. The last one is the reason this file exists.

```json
{
  "id":       "V1-03",
  "spec":     "§1",
  "claim":    "an implementation MUST fail rather than continue past counter = 256",
  "given":    { "base": "0x0000…0000" },
  "expect":   { "counter": 1, "offset": "0x…" },
  "wrong":    "counter 0 accepted — an implementation that does not range-check base
               returns offset = 0, and every payment derived from it is unspendable"
}
```

**`claim`** quotes the normative sentence and **`wrong`** is the discriminating half.

### Two tiers

| tier | covers | oracle | who generates it |
|---|---|---|---|
| 1 | ML-KEM-768 itself | **FIPS 203 / NIST ACVP** | nobody — vendored at a pinned commit |
| 2 | **everything below** | the specification text | a standalone generator, no project code |

Tier 2 needs only **SHA3-256**, SHA-256, HKDF-SHA256, secp256k1 and keccak-256. **No
lattice arithmetic**, which is exactly why it can be written before any of this is
implemented.

---

## 2. §1 — common to every schemeId

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V1-01 | `H(ss) = SHA256(DS_offset ‖ ss)`, reduced | a fixed `ss` | `base`, `offset`, `counter = 0` | — |
| V1-02 | **every digest is big-endian** | an `ss` whose digest starts `0x01` and ends `0x80` | the integer, MSB first | little-endian read gives a different scalar, therefore a different address, therefore **funds the recipient cannot spend**. Silent and total |
| V1-03 | reduction MUST reject `base = 0` | `base = 0x00…00` | `counter = 1`, `offset = SHA256(DS ‖ base ‖ 0x01)` | `counter = 0` and `offset = 0` — no range check |
| V1-04 | reduction MUST reject `base = n` | `base = n_secp256k1` | `counter = 1` | accepted as valid; some libraries reduce mod n silently and return 0 |
| V1-05 | `base = n − 1` is **valid** | `base = n − 1` | `counter = 0` | rejected — an off-by-one in the bound loses a legitimate payment |
| V1-06 | the counter byte is a single byte appended | a `base` forced to counter 1 | a pinned 32-byte output | `u32` or `u64` counter encoding; ASCII `"1"` |
| V1-07 | `view_tag = SHA256(DS_viewtag ‖ ss)[0]` | a fixed `ss` | one byte | **the superseded eight-byte width**, `[0..8]`, which matches nothing a conforming sender emits; taking `[31]` instead of `[0]`; or the leading byte of `H(ss)` instead of a separate digest |

## 3. §2.9 — schemeId 3 (hedged EC half)

> **What left with schemeId 2, named rather than dropped quietly.** This set was written as a
> delta on a KEM-only rung that no longer ships, and its thirteen rows went with it. **Five
> were already covered here** by a schemeId 3 equivalent: the keygen-seed length rejection
> (V3-01), the 65-offset delegation window scan (V3-02), the meta-address encoding (V3-03),
> the SEC1 `0x02`/`0x03` tag rule (V3-03), and the announcement's wire shape (V3-08).
>
> **Eight rules the specification still states for this rung lost their only fixture.**
> Nothing in this tree pins them now:
>
> | rule | stated at |
> |---|---|
> | keygen is deterministic in the seed — the same 128 bytes give the same three keys | §2.1 |
> | `spending_seed` MUST be a valid secp256k1 scalar | §2.1, §2.7 |
> | decode MUST reject a meta-address of any length but 1 250 | §2.2, §2.7 |
> | 33 bytes of the right length can still be a non-point | §2.2, §2.7 |
> | `address = keccak256(uncompressed(pk)[1..])[12..32]` | §2.4 |
> | a view-tag mismatch is a skip — **and decapsulation does not fail** | §2.7 |
> | a malformed `ct` is a skip at the entry point, not an error | §2.7 |
> | the derived key controls the derived address, as a key-to-address relation | §2.6 |
>
> The sixth is the one to weigh: it was the only fixture exhibiting **ML-KEM's implicit
> rejection** — a foreign ciphertext yielding a pseudorandom secret and no error — which is
> the fact §2.4's required address comparison and §1's one-byte tag are both built on. The
> specification asserts it; no fixture demonstrates it any more.
>
> These are recoverable as schemeId 3 rows. They were not re-homed in the pass that removed
> schemeId 2, because a re-homed row is a **new value** that the blinded re-derivation
> (`rederivation.json`) has never witnessed, and quietly adding unwitnessed rows to a set
> whose whole claim is independent witness is a worse trade than a stated gap.
>
> **§5's seed-derivation group went in the same pass, and for a different reason.** Its five
> rows pinned `keygen_seed` and `announce_seed` — the HKDF and SHAKE256 field orders, the
> length-prefixed `kem_id`, and index advance on a rejected seed. **This specification states
> none of them**: `keygen_seed`, `announce_seed`, `SHAKE256` and `kem_id` appear nowhere in
> it. A fixture with no normative sentence behind it is the thing §1 of this plan says gets
> deleted rather than argued about, so it was. Their subject is how a wallet derives many
> schemes' keys from one master, which is a wallet concern rather than a wire-format one; if
> it returns to this document, the rows return with it.

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V3-01 | keygen seed is 128 B | 128 B; then 96 B and 127 B | outputs; then errors | accepting schemeId 2's 96-byte seed |
| V3-02 | the delegation check scans the **96-byte delegated object** at all 65 offsets | `spending_seed` at offset **0** (wholly inside `viewing_ec_seed` — the only such offset); at **40 and 47** (wholly inside `kem_seed`); **and at 5, 16 and 20 — straddling the boundary**. The grouping is load-bearing: a 32-byte window at offset 5 spans bytes 5 to 36, so a per-half scan misses it | error, all five times | **scanning the two halves separately.** That covers 34 offsets and accepts the three straddling cases, placing the spending seed verbatim in the bytes handed to a scanning service |
| V3-02a | a keygen with no coincidence is accepted | a seed whose delegated object contains no window equal to `spending_seed` | outputs, no error | rejecting valid keygens — the positive control, without which V3-02 passes on an implementation that rejects everything |
| V3-03 | meta is 1 250 B and **both** points are validated | a `0x05`-tagged `viewing_pk_ec`, `spending_pk` well-formed | error at decode | validating only `spending_pk`, which is the natural port of §2's decoder |
| V3-04 | `ss_ec` is the **x-coordinate alone** | `esk`, `viewing_pk_ec` | 32 bytes | the full 65-byte point, or the 33-byte compressed form → a different `ss`, silently |
| V3-05 | the domain separator is the **first** input, neither appended nor length-prefixed | the IKM above | 32-byte `ss` | appending it, or length-prefixing it → a different `ss`, silently. This is the parameter that replaced the absent-salt requirement when the derivation became a direct hash, and no other vector pinned it |
| V3-06 | IKM is exactly `ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek`, in that order | the six parts | 32-byte `ss` | any other order, and **any omission** → a different `ss`. The three-field form `ss_ec ‖ ss_pq ‖ epk` is what both implementations produce today and is the likeliest wrong answer |
| V3-06a | `ct` is bound in | two announcements with the same `epk` and `ss_ec` but different `ct` | different `ss` | the same `ss` — the case SP 800-227 section 4.6.3's argument turns on |
| V3-06b | `viewing_pk_ec` is bound in | the same `ss_ec` reached against two recipients' registered keys | different `ss` | the same `ss`, which is the identity binding absent from the old IKM |
| V3-07 | `epk` MUST be bound in | the same first contact with the parity byte flipped `0x02`↔`0x03` | a **different** `ss` | the same `ss` — the flipped point has the same x-coordinate, so without `epk` in the IKM this is a replay with a different-looking announcement |
| V3-08 | wire shape | the sender above | `epk` 33 in `ephemeralPubKey`, **`view_tag ‖ ct`** 1 089 in `metadata`, 1 122 B | §2's field convention, which this variant does not use; **or the reversed field order**, which puts the view tag at `metadata[1088]` — the same length as the right answer, so no length check distinguishes it |
| V3-08a | the view tag is `metadata[0]` | a real payment, and a foreign announcement | matched; skipped | comparing against the first byte of `ct` — a scanner that agrees 1 time in 256 by coincidence, so it misses most payments to it and finds the occasional one. An intermittent fault, and harder to chase than a clean empty scan |

## 7. Deliverables, in order

1. `tools/gen_vectors.py` — standalone, `hashlib` plus one secp256k1 library, **imports
   nothing from this repository.** Emits one JSON file per section plus a manifest with a
   sha256 per file.
2. `vectors/*.json` — the sets above, committed.
