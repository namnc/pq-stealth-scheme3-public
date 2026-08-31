# Conformance vector plan — schemeId 3, and what it shares

## 1. Each test vector is explainable

Every vector is a JSON object with six fields, e.g.

```json
{
  "id":       "V1-03",
  "spec":     "Section 1",
  "claim":    "an implementation MUST fail rather than continue past counter = 256",
  "given":    { "base": "0x0000…0000" },
  "expect":   { "counter": 1, "offset": "0x…" },
  "wrong":    "counter 0 accepted — an implementation that does not range-check base
               returns offset = 0, and every payment derived from it is unspendable"
}
```

### Two tiers of test vectors

| tier | covers | oracle | who generates it |
|---|---|---|---|
| 1 | ML-KEM-768 itself | **FIPS 203 / NIST ACVP** | nobody — vendored at a pinned commit |
| 2 | **everything below** | the specification text | a standalone generator, no project code |

---

## 2. Section1 — common to every schemeId

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V1-01 | `H(ss) = SHA256(DS_offset ‖ ss)`, reduced | a fixed `ss` | `base`, `offset`, `counter = 0` | — |
| V1-02 | **every digest is big-endian** | an `ss` whose digest starts `0x01` and ends `0x80` | the integer, MSB first | little-endian read gives a different scalar, therefore a different address, therefore **funds the recipient cannot spend**. Silent and total |
| V1-03 | reduction MUST reject `base = 0` | `base = 0x00…00` | `counter = 1`, `offset = SHA256(DS ‖ base ‖ 0x01)` | `counter = 0` and `offset = 0` — no range check |
| V1-04 | reduction MUST reject `base = n` | `base = n_secp256k1` | `counter = 1` | accepted as valid; some libraries reduce mod n silently and return 0 |
| V1-05 | `base = n − 1` is **valid** | `base = n − 1` | `counter = 0` | rejected — an off-by-one in the bound loses a legitimate payment |
| V1-06 | the counter byte is a single byte appended | a `base` forced to counter 1 | a pinned 32-byte output | `u32` or `u64` counter encoding; ASCII `"1"` |
| V1-07 | `view_tag = SHA256(DS_viewtag ‖ ss)[0]` | a fixed `ss` | one byte | **the superseded eight-byte width**, `[0..8]`, which matches nothing a conforming sender emits; taking `[31]` instead of `[0]`; or the leading byte of `H(ss)` instead of a separate digest |

## 3. Section2.9 — schemeId 3 (hedged EC half)

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V3-01 | keygen seed is 128 B | 128 B; then 96 B and 127 B | outputs; then errors | accepting a legacy 96-byte seed |
| V3-02 | the delegation check scans the **96-byte delegated object** at all 65 offsets | `spending_seed` at offset **0** (wholly inside `viewing_ec_seed` — the only such offset); at **40 and 47** (wholly inside `kem_seed`); **and at 5, 16 and 20 — straddling the boundary**. The grouping is load-bearing: a 32-byte window at offset 5 spans bytes 5 to 36, so a per-half scan misses it | error, all six times | **scanning the two halves separately.** That covers 34 offsets and accepts the three straddling cases, placing the spending seed verbatim in the bytes handed to a scanning service |
| V3-02a | a keygen with no coincidence is accepted | a seed whose delegated object contains no window equal to `spending_seed` | outputs, no error | rejecting valid keygens — the positive control, without which V3-02 passes on an implementation that rejects everything |
| V3-03 | meta is 1 250 B and **both** points are validated | a `0x05`-tagged `viewing_pk_ec`, `spending_pk` well-formed | error at decode | validating only `spending_pk`, which is the natural port of Section2's decoder |
| V3-04 | `ss_ec` is the **x-coordinate alone** | `esk`, `viewing_pk_ec` | 32 bytes | the full 65-byte point, or the 33-byte compressed form → a different `ss`, silently |
| V3-05 | the domain separator is the **first** input, neither appended nor length-prefixed | the IKM above | 32-byte `ss` | appending it, or length-prefixing it → a different `ss`, silently. This is the parameter that replaced the absent-salt requirement when the derivation became a direct hash, and no other vector pinned it |
| V3-06 | IKM is exactly `ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek`, in that order | the six parts | 32-byte `ss` | any other order, and **any omission** → a different `ss`. The historical three-field form `ss_ec ‖ ss_pq ‖ epk` is the likeliest omission |
| V3-06a | `ct` is bound in | two announcements with the same `epk` and `ss_ec` but different `ct` | different `ss` | the same `ss` — the case SP 800-227 section 4.6.3's argument turns on |
| V3-06b | `viewing_pk_ec` is bound in | the same `ss_ec` reached against two recipients' registered keys | different `ss` | the same `ss`, which is the identity binding absent from the old IKM |
| V3-07 | `epk` MUST be bound in | the same first contact with the parity byte flipped `0x02`↔`0x03` | a **different** `ss` | the same `ss` — the flipped point has the same x-coordinate, so without `epk` in the IKM this is a replay with a different-looking announcement |
| V3-08 | wire shape | the sender above | `epk` 33 in `ephemeralPubKey`, **`view_tag ‖ ct`** 1 089 in `metadata`, 1 122 B | Section2's field convention, which this variant does not use; **or the reversed field order**, which puts the view tag at `metadata[1088]` — the same length as the right answer, so no length check distinguishes it |
| V3-08a | the view tag is `metadata[0]` | a real payment, and a foreign announcement | matched; skipped | comparing against the first byte of `ct` — a scanner that agrees 1 time in 256 by coincidence, so it misses most payments to it and finds the occasional one. An intermittent fault, and harder to chase than a clean empty scan |
| V3-09 | **keygen MUST be deterministic in the seed** | a 128-byte seed whose `kem_seed` is ACVP keygen `(d, z)`, so `ek` is NIST's value | the 1 250-byte meta-address, the 96-byte tracking key, the 32-byte master | calling the KEM's randomness-taking keygen and ignoring `kem_seed` — the entry point most ML-KEM APIs offer first. The meta-address is well formed and registration succeeds; nothing fails until the owner restores from seed, gets a different `dk`, and can decapsulate no payment ever made to the registered `ek` |
| V3-10 | `spending_seed` and `viewing_ec_seed` MUST each be a valid secp256k1 scalar | 128-byte seeds differing only in one 32-byte half: `0`, `n`, `n − 1`, and `viewing_ec_seed = 0` | error, error, **accepted**, error | reducing the seed mod n rather than rejecting it. Section1's counter-reduction is for the offset *base*, not for a seed: `spending_seed = n` becomes `0`, and every payment to the resulting meta-address is spendable by anyone. `n − 1` is the positive control |
| V3-11 | decoding MUST reject a meta-address length other than 1 250 | 1 249, 1 250, 1 251 | error, accepted, error | slicing `[0:33]`, `[33:66]`, `[66:]` with no length check: 1 251 decodes with a trailing byte ignored, 1 249 yields a 1 183-byte `ek` the KEM rejects at the first payment rather than at decode |
| V3-12 | 33 bytes of the right length can still be a **non-point** | `0x02 ‖ x` for `x = 5`, the smallest `x` with no `y` on the curve; then a valid key | error at decode, then accepted | checking the length and the `0x02`/`0x03` tag byte and storing the bytes. The ECDH that follows throws from inside a curve library, far from the meta-address that caused it — or, in a library that does not validate, returns a value on the wrong curve |
| V3-13 | `address = keccak256(uncompressed(pk)[1..])[12..32]` | a derived `stealth_pk`, both encodings | the 20-byte address and its EIP-55 form | keccak of the *compressed* form; keccak *with* the `0x04` prefix; `[0..20]` rather than `[12..32]`. Each is 20 well-formed bytes and each is a different address — the payment is lost to a chain address nobody holds a key for, not to an error |
| V3-14 | a view-tag mismatch is a skip — **and decapsulation does not fail** | ACVP decapsulation tcId 88, `reason: modified ciphertext`; `ek` read from `dk[1152:2336]` and checked against the `H(ek)` at `dk[2336:2368]` | 32 bytes and **no error**; a derived tag differing from the announced one; **skip** | scanning on whether `Decaps` errored — it never does, so such an implementation matches every announcement ever published. Raising on the mismatch is the other error: `announce()` is permissionless, so an error path there is a scanner denial of service (Section2.4) |
| V3-15 | a malformed `ct` is a **skip at the entry point**, not an error | `metadata` of 1 088, 1 089, 1 090 B; `ephemeralPubKey` of 32 and 33 B | skip for every shape but 1 089 / 33 | raising, or propagating a library exception. Anyone can call `announce()` with any bytes, so a scanner that errors on shape stops at the first announcement an attacker publishes, for the price of one transaction. The 1 089 case is the positive control |

## 7. Deliverables, in order

1. `tools/gen_vectors.py` — standalone, `hashlib` plus one secp256k1 library, **imports
   nothing from this repository.** Emits one JSON file per section plus a manifest with a
   sha256 per file.
2. `vectors/*.json` — the sets above, committed.
