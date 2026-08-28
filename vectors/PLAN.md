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

- **`claim`** quotes the normative sentence. A vector with no sentence behind it is a
  vector somebody invented, and it gets deleted rather than argued about.
- **`wrong`** is the discriminating half. A test that cannot say what failure looks like
  cannot distinguish a passing implementation from an untested one — the same gate the
  crates are held to, applied to fixtures.

**Almost every `wrong` below is a defect that actually happened**, in this project or in
its reference implementations. That is the honest summary of what this vector set is: the
project's own findings, turned into fixtures a third implementer inherits for free.

### Two tiers

| tier | covers | oracle | who generates it |
|---|---|---|---|
| 1 | ML-KEM-768 itself | **FIPS 203 / NIST ACVP** | nobody — vendored at a pinned commit |
| 2 | **everything below** | the specification text | a standalone generator, no project code |

Tier 2 needs only **SHA3-256**, SHA-256, HKDF-SHA256, secp256k1 and keccak-256. **No
lattice arithmetic**, which is exactly why it can be written before any of this is
implemented.

> **`SHA3-256` is in this list deliberately.** The shared-secret and
> channel-key combiners are direct `SHA3-256` hashes, and `SHA3-256` is
> **not** `keccak-256` — different padding, different digest for the same input. A generator
> that reads `keccak-256` here cannot produce `V3-05`, `V3-06` or `V4-01` at all.
> `HKDF-SHA256` stays, because `keygen_seed` still uses it.

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

## 3. §2 — schemeId 2

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V2-01 | keygen seed is 96 B and keygen is deterministic | a 96-byte seed | meta-address, master, tracking — **twice, identical** | nondeterminism, which makes every vector below unusable |
| V2-02 | MUST reject any other length | 95 B, 97 B, 0 B | error at keygen | padding or truncating to 96 |
| V2-03 | `spending_seed` MUST be a valid scalar | `0x00…00`, then `n` | error at keygen | accepted; `SecretKey::from_slice` catches one of these but not both in every library |
| V2-04 | delegation check is a **32-byte window scan** | `kem_seed` with `spending_seed` at offset **17** | error at keygen | **accepted.** A prefix-only comparison passes this, and the tracking key then contains the master spending key verbatim — reproducible end to end against a real payment |
| V2-05 | `meta = spending_pk(33) ‖ ek(1184)` = 1 217 B | the keygen above | the exact byte string | field order swapped; a length prefix added |
| V2-06 | decode MUST reject any other length | 1 216 B, 1 218 B | error at decode | trailing bytes ignored |
| V2-07 | tag MUST be `0x02`/`0x03` **only** | a `0x05`-tagged encoding of the same point | error at decode | **accepted.** The RustCrypto `sec1` stack canonicalises `0x05` to the same point, so one key gets two on-chain encodings and an attacker picks which recipients see. The two reference implementations **disagreed on this** |
| V2-08 | 33 bytes of right length can still be a non-point | `0x02 ‖ 32 × 0xff` | error at decode | accepted, then a curve operation on garbage |
| V2-09 | `address = keccak256(uncompressed(pk)[1..])[12..32]` | a `stealth_pk` | 20 bytes, plus its EIP-55 form | including the `0x04` prefix in the hash; taking `[0..20]` |
| V2-10 | announcement is `ct` in `ephemeralPubKey`, `view_tag` (1 B) in `metadata` | the sender above | the two field byte strings, 1 088 and 1 | the two fields swapped — which is §3's convention and is wrong here; or an eight-byte `metadata`, the superseded width, which no scheme in the specification emits any more |
| V2-11 | view-tag mismatch → **skip** | a foreign well-formed `ct` | not mine, no error | an error, which per §2.5 aborts the whole scan |
| V2-12 | malformed `ct` → **skip at the entry point** | `ct` of 1 087, 0 and 1 089 bytes | not mine, no error, ×3 | an error. Both references are layered so the entry point converts it; an implementation exposing the inner routine as its scanning API inherits the wrong behaviour |
| V2-13 | the derived key controls the derived address | the vector above | `spend_key_controls` true, **as a key-to-address relation** | asserting only that bytes were produced — a derivation can be self-consistent and wrong |

## 4. §2.9 — schemeId 3

Everything in §3 above applies. These are the additions.

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
| V3-08 | wire shape | the sender above | `epk` 33 in `ephemeralPubKey`, **`view_tag ‖ ct`** 1 089 in `metadata`, 1 122 B | §2's field convention, which this variant does not use; **or the reversed field order**, which puts the view tag at `metadata[1088]`. **This shape is byte-identical to a schemeId 5 first contact** — §6 declares the collision, so a fixture asserting the two differ would assert the reversed order |
| V3-08a | the view tag is `metadata[0]` | a real payment, and a foreign announcement | matched; skipped | comparing against the first byte of `ct` — a scanner that agrees 1 time in 256 by coincidence, so it misses most payments to it and finds the occasional one. An intermittent fault, and harder to chase than a clean empty scan |

> **V3-05 and V3-06 are marked `provisional` in the generated files.** §2.9's domain separator
> string is new in this document and **no outside implementation has adopted it** — this project's
> own implementation produces these bytes and the blinded re-derivation agreed on them, and neither
> is an outside party. (An implementation in this repository producing these bytes does
> not change that.) §3's
> equivalent parameters were discovered *after* two implementations already matched; these
> have nothing to match yet. The vector is what turns the proposal into the specification,
> so the flag comes off when the author confirms the string.
>
> **`V3-05` does not mention a salt.** A direct hash has no salt, and §3.3 item 2
> says in terms that the absent-salt requirement was *replaced* by the domain-separator
> rule rather than answered. This note called the same string an `info` parameter for the
> same reason. A fixture generated from either would have tested a parameter that does not
> exist, which is worse than a missing vector: it would pass.

## 6a. §5 — seed derivation

Three rules here would otherwise have no vectors because §5 is where their specification lives.

> **The fourth row earns its place.** §5 specifies
> *two* derivations — the keygen seed and the **announce seed** — and a suite where only
> the keygen half has a row leaves the announce half a derivation nothing can disagree
> with. The two ways it goes wrong while every constant is quoted correctly: the index
> appended last where §5 puts it immediately after `master`, and `kem_id` absent entirely.
>
> `V6-05` below is that fixture, and it pins the field ORDER — exactly the thing a
> string-shape gate cannot catch, because every constant involved can be quoted from
> the specification correctly and still assembled in the wrong order.

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V6-01 | `keygen_seed(schemeId, rung, j) = HKDF(keygen_master, absent salt, "pq-stealth/keygen/v1" ‖ u64be(schemeId) ‖ u64be(\|rung\|) ‖ rung ‖ u64be(j), L)`, **with `j = 0` on the normal path** | one `keygen_master`, schemeIds 2 and 3 | a 96-byte and a 128-byte seed | a fixed `L = 32`; a supplied salt; omitting the scheme name, which collides two schemes sharing a `schemeId` |
| V6-02 | two schemes' keys from one master are **independent** | the seeds of V6-01 | no shared bytes, and neither recoverable from the other | deriving one from the other, or reusing one keygen seed under two `schemeId`s |
| V6-03 | an `ephemeral_seed` that is not a valid scalar advances the index | **a chosen seed injected through the conformance hook, not a searched `master`** | the announcement uses index `i+1`; index `i` never reappears | failing hard; or retrying index `i`, which breaks the injectivity of the seed stream |
| V6-04 | a rejected keygen seed advances the index of **that (`schemeId`, `rung`) pair and no other**, and does not change `keygen_master` | a `keygen_master` and one rung whose index-0 seed fails the scalar or delegation test, with a second rung of the same `schemeId` already registered | index 1 accepted; **every other scheme's keygen seed unchanged** | drawing a fresh `keygen_master`, which changes a funded scheme's keys |
| V6-05 | `announce_seed = SHAKE256(DS ‖ master(32) ‖ u64be(i) ‖ u64be(schemeId) ‖ u64be(\|rung\|) ‖ rung ‖ u64be(\|kem_id\|) ‖ kem_id, n)`, **in exactly that field order**, with `kem_id = u64be(\|name\|) ‖ name` = 18 B for `"ML-KEM-768"` | one `master`, schemeId 2 at index 0 and 1, schemeId 3 at index 0 | three seeds of the specified lengths, and the schemeId 3 seed's 32/32 split | **appending `i` last instead of placing it after `master`**, and **omitting `kem_id`** — two errors this repository's own generator once made, each of which yields a well-formed seed that no conforming implementation reproduces. Also: an unprefixed `kem_id`, or naming a wrapper instead of what it wraps |


## 7. Deliverables, in order

1. `tools/gen_vectors.py` — standalone, `hashlib` plus one secp256k1 library, **imports
   nothing from this repository.** Emits one JSON file per section plus a manifest with a
   sha256 per file.
2. `vectors/*.json` — the sets above, committed.
3. a directory note beside them, where a tree carries one — what each file pins, and the
   tier-1 vendoring pointer.
