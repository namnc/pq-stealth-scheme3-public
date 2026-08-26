# Conformance vector plan — schemeIds 2 to 6

**Written before any implementation.** The point of reviewing this file rather
than a diff: if the vectors are right, an implementation that passes them is conformant,
and if they are wrong no amount of passing helps. So they are written from the
specification text, by a generator that imports no project code, and **each one says what
a wrong implementation produces instead.**

**The rule these follow, stated here rather than pointed at:** vectors are derived from the
specification, never from an implementation, because generating them from an implementation
lets an implementation bug become the standard. It is written out here, in the file the rows
live in, because this file travels into trees that carry the fixtures without a directory note
beside them -- and a rule a reader has to go and find is a rule that gets skipped.

> **What the generator emits, measured: every generatable row of all three waves; three
> rows are recorded as `not_generatable` with the reason.** `V6-03` needs a rejection injected
> past the derivation — a harness hook rather than a fixture, exactly as `V1-08` already is; no
> KEM closes it, so it is not waiting on anything. `V6-17` and `V6-18` need lattice
> arithmetic derived from the prose that this generator does not have.
>
> **The oracle is `kyber-py`, a third-party ML-KEM, and its acceptance test is that it
> reproduces the vendored NIST ACVP file.** It does — the keygen, encapsulation and
> decapsulation tuples, the implicit-rejection cases among them — and the check **runs on
> every generator invocation rather than once by hand.** A disagreement is a hard failure,
> because every KEM-bearing row would otherwise be built on it silently.
>
> Two properties make this the right oracle rather than a convenience. It satisfies the
> standalone rule completely — that rule forbids importing the code the vectors validate, which
> is *ours*, and a Python implementation is necessarily a different implementation from the Rust
> we ship. And the trust question has an **answer** rather than an assurance: it is trusted for
> exactly the tuples it reproduces from NIST, and nothing else.
>
> **The dependency is OPTIONAL to the generator**, which runs from a bare checkout and records
> the KEM-bearing rows — `V2-01`, `V2-11`, `V2-13` in wave 1, three in wave 2, and `V6-14`,
> `V6-16` in wave 3 — as `not_generatable` with the reason
> when it is absent. `gen_vectors.py --check`
> compares the committed files against a fresh generation, so a set produced under a different
> availability cannot pass unnoticed. A bare emitted-count is deliberately not written here:
> the coverage gate in the authoring repository computes four counts and objects to any figure that is not
> one of them, on the ground that an unlabelled number passes by coincidence rather than by
> being right — with the ML-KEM installed, a full run emits every row but the three this
> paragraph opened by recording as `not_generatable`: `V6-03`, `V6-17` and `V6-18`. The KEM
> closes the KEM-bearing rows and none of those three, which is the point of listing them
> separately.
>
> > **A finding about ACVP, measured:** its keyGen and encapsulation cases use disjoint
> > keys, so no vector needing one key's `(d, z)` seed *and* a ciphertext encapsulated to
> > it can be built from ACVP alone — which is why the KEM-bearing rows are
> > unreachable without an ML-KEM library. The vendored ACVP file is the library's
> > committed acceptance test rather than the generator's data source, which is the
> > better job for it.
>
> **Nothing is approximated.** A fabricated `ct` or `ss` in a conformance fixture would be
> worse than a missing one, because it would pass.

**Where the sections in the group headings below live.** The specification is written as
four documents and the section numbering is shared across them, so the headings are unchanged
and each `§N` resolves in whichever document owns it: `§1`, `§5`, `§6`, `§7`, `§8` and `§9`
in the common-definitions document; `§2` in the per-payment document; `§3` in the channel
document; `§4` in the post-quantum-spending document. The coverage table in §7a is generated
per document and names all four.

*Cited by name rather than by path, deliberately.* A tree may carry these fixtures together
with only one of those documents -- the standalone single-rung export does exactly that -- and
a path here would then be a dead link in the first note a reader reads.

**And in such a tree, the rows for the absent documents cannot be audited from it.** Every
row states the normative sentence it pins, and a reader holding one document can check the
rows for that document against its text and no others. The rest remain runnable fixtures
with a stated intent and no local authority to check that intent against. Saying so is the
point of this paragraph: shipping the suite whole keeps the generator and the manifest
honest, and it does not turn a reader holding one document into a reader who can review
four.

---

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

### Three tiers, three oracles

| tier | covers | oracle | who generates it |
|---|---|---|---|
| 1 | ML-KEM-768 itself | **FIPS 203 / NIST ACVP** | nobody — vendored at a pinned commit |
| 2 | **everything below** | the specification text | a standalone generator, no project code |
| 3 | Spirit / schemeId 6 | the authors' C at `f99f1e1` | exists; stays separate as *parity* vectors |

Tier 2 needs only **SHA3-256**, SHA-256, HKDF-SHA256, secp256k1 and keccak-256. **No
lattice arithmetic**, which is exactly why it can be written before any of this is
implemented.

> **`SHA3-256` is in this list deliberately.** The shared-secret and
> channel-key combiners are direct `SHA3-256` hashes, and `SHA3-256` is
> **not** `keccak-256` — different padding, different digest for the same input. A generator
> that reads `keccak-256` here cannot produce `V3-05`, `V3-06` or `V4-01` at all.
> `HKDF-SHA256` stays, because `keygen_seed` still uses it.

### One thing the vectors force on the API, and it is worth knowing early

**The scalar-reduction retry path cannot be tested through a public interface that only
takes `ss`.** `offset = H(ss)` is a pure function, so a vector that supplies `ss` can never
reach counter ≥ 1 — the values that would need it are not findable. The reference's own
test falls into exactly this trap: it asserts `stealthOffset(ss) ==
stealthOffset(copy_of_ss)`, a tautology for a pure function, while being named for the
retry path.

So conformance requires the reduction to be **callable with a chosen `base`** — as an
exposed function, a test hook, or a documented internal. §1 gives the procedure in full;
this is the API consequence of testing it, and it should be stated in §1 rather than
discovered by the first implementer who tries. **Recorded as a spec gap, not fixed here.**

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
| V1-07 | `view_tag = SHA256(DS_viewtag ‖ ss)[0..8]` | a fixed `ss` | eight bytes | **taking `[0]` alone — the superseded one-byte width, which a port will reach for**; taking `[24..32]`; or the leading bytes of `H(ss)` instead of a separate digest |

**V1-08 is deliberately absent.** Counter exhaustion — 257 distinct inputs then failure —
cannot be reached by any constructible input, so it is a harness assertion over a stubbed
digest, not a fixture. Named here so its absence is not mistaken for coverage.

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
| V2-10 | announcement is `ct` in `ephemeralPubKey`, `view_tag` (8 B) in `metadata` | the sender above | the two field byte strings, 1 088 and 8 | the two fields swapped — which is §3's convention and is wrong here; or a one-byte `metadata`, which no scheme in the specification emits |
| V2-11 | view-tag mismatch → **skip** | a foreign well-formed `ct` | not mine, no error | an error, which per §2.5 aborts the whole scan |
| V2-12 | malformed `ct` → **skip at the entry point** | `ct` of 1 087, 0 and 1 089 bytes | not mine, no error, ×3 | an error. Both references are layered so the entry point converts it; an implementation exposing the inner routine as its scanning API inherits the wrong behaviour |
| V2-13 | the derived key controls the derived address | the vector above | `spend_key_controls` true, **as a key-to-address relation** | asserting only that bytes were produced — a derivation can be self-consistent and wrong |

**V2-14 exists as a question, not a vector.** The announced `stealthAddress` versus the
derived one: §2.8 leaves the disposition open (`the announced-address comparison is a MAY), so the fixture
would have to encode an undecided rule. Held until D6 is answered.

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
| V3-08 | wire shape | the sender above | `epk` 33 in `ephemeralPubKey`, **`view_tag ‖ ct`** 1 096 in `metadata`, 1 129 B | §2's field convention, which this variant does not use; **or the reversed field order**, which puts the view tag at `metadata[1088]`. **This shape is byte-identical to a schemeId 5 first contact** — §6 declares the collision, so a fixture asserting the two differ would assert the reversed order |
| V3-08a | the view tag is `metadata[0..8]` | a real payment, and a foreign announcement | matched; skipped | comparing against the first eight bytes of `ct` — a scanner that misses **every** payment to it, silently, reporting a clean empty scan. Worse than the one-byte case, which matched 1 in 256 and left a symptom to chase |

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

## 5. §3 — schemeId 4

> **The two channel sections divide as §2 does**: §3.1–§3.11
> specify schemeId 4 in full and §3.12 gives schemeId 5 as the delta, matching §2's direction.
>
> **The row IDS did not move, and that is deliberate.** `V4-*` are schemeId 4's rows and `V5-*`
> are schemeId 5's, which is the mapping the ids themselves imply; renumbering to follow the
> section order would break every existing reference to these ids for no gain. **The consequence
> to be aware of: the rows shared by both rungs — the memo, the nonce, the retention rules, the
> skip dispositions — carry `V5-*` ids while belonging to the base rung.** They are listed under
> §3.12 below and each says so.

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V4-01 | `k_pairwise = SHA3-256("pq-stealth/pairwise-pq/v1" ‖ ss_pq)` — a **direct hash**, not HKDF | a first contact | 32-byte key | binding `ct` in as well, which is the candidate the author rejected, or reusing schemeId 5's separator |
| V4-02 | the derivation **differs** from schemeId 5's on the same inputs | the same `ss_pq` under both domain separators | two different keys | the same key — the domain separation this pins is the whole reason both strings are stated |
| V4-03 | first contact is empty `ephemeralPubKey`, **`view_tag ‖ ct`** 1 096 in `metadata` | a new channel | 1 096 B | `ct` in `ephemeralPubKey`, which is schemeId 2's convention and which no length check distinguishes; **or `ct` alone with no tag — the shape the older references emit, and the one a port will produce** |
| V4-03a | the first contact's own view tag verifies at **counter 0**, and that is what admits the channel | a first contact addressed to this recipient, and one addressed to a stranger | admitted; discarded with nothing retained | admitting on decapsulation alone, which retains one channel per first contact ever seen; or deriving the tag at counter 1, which matches nothing |
| V4-03b | the admitted first contact is **also a payment**, at counter 0 | the first contact above | a derived stealth address, and the payment found at it | admitting the channel and deriving no payment — **the first payment on every channel, lost systematically with no error** |
| V4-04 | meta-address is 1 217 B with **one** point | `spending_pk ‖ ek` | accepted; 1 250 B rejected | validating two points, ported from schemeId 5's decoder |
| V4-06 | keygen seed is 96 B, and the delegated object is `kem_seed` alone | 96 B; then 128 B | outputs; then error | accepting schemeId 5's 128-byte seed. **The 65-offset scan of V3-02 does not apply here** — with one delegated secret, §2.1's scan over `kem_seed` is already complete |
| V4-07 | keygen scans the 64-byte `kem_seed` for `spending_seed` at all **33 offsets** and refuses the coincidence | `spending_seed` planted at offsets 0, 16 and 32; and a clean `kem_seed` | error, all three; outputs on the clean control | **omitting the scan** — no other committed schemeId 4 row reaches it, so a port that skips it passes this file while handing the spending seed to a scanning service. V3-02 and V5-01 witness only the 65-offset two-secret form, in files a scheme-4-only port never loads |

**Eight vectors, one of them withdrawn** — described here in prose and
not in a second table, because a table row carrying an id is a **vector row** to
the coverage gate in the authoring repository, and listing an id twice makes it a duplicate:

- **`V4-05` is withdrawn**: ~~a combined announcement is not published, at 1 113 B~~. The
  combined announcement is the specified shape (§3.4), at 1 096 B. A fixture asserting it
  unrecognised would certify a scanner that rejects every conforming first contact.
- **`V4-03a` is new.** The view-tag gate on the first contact is what replaced the confirm tag,
  and it is §9's anti-griefing requirement. Nothing pinned it before, because the gate lived on a
  memo.
- **`V4-03b` is new.** §3.6 requires the gating announcement's payment to be derived. That was a
  vector for the gating *memo*, `V5-19`; it is now one for the first contact, which a scanner
  reaches by a different code path — so the loss it guards against became easier to hit, not
  harder.
- **`V4-07` is new.** The §2.1 scan over the delegated `kem_seed` gets its own planted-offset
  witness. Its absence is the exact gap the delegation guard exists to close: a scheme-4-only
  port that omits the scan passes every other committed row while a tracking delegation can
  carry the spending seed verbatim.

## 6. §3.12 — schemeId 5

**Everything in §5 above carries over**, plus the EC half: V5-01's wider delegation scan,
V5-02's combined channel key, V5-03's `epk` binding, V5-07's `epk` on the wire and V5-09's `epk`
decoder cases. **Rows below whose claim is not hybrid-specific belong to both rungs** and carry
`V5-*` ids for the reason the note in §5 gives.

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V5-01 | 128-byte seed; the `spending_seed` scan covers the **whole 96-byte delegated object**, 65 offsets, not each half's 34 | as V3-01, V3-02 | as above | as above. **Not "both delegated halves checked"** — a per-half scan accepts the 31 straddling offsets and puts the spending key inside delegated scanner material |
| V5-02 | the channel key's parameters | a first contact | `k_pairwise` | as V3-04, V3-05, V3-06, V3-06a, V3-06b — the same failure modes, different domain separator. **Both implementations currently derive the three-field IKM**, so this vector fails against both until the port lands |
| V5-03 | `epk` bound into the channel KDF | parity-flipped `epk` | a different `k_pairwise` | the same key — the replay §3.3 exists to stop |
| V5-04 | the counter is `NONCE_BYTES`-byte **big-endian** in the DERIVATION and appears on no wire, and a **memo** starts at counter 1 | a new channel, second payment | the payment secret and view tag at counter 1, and a memo of exactly 8 bytes | 8-byte or little-endian counter encoding, which gives a different `ss` silently; **publishing the counter**, which is not a wire field; **starting a memo at 0**, which is the first contact's counter and re-derives its address |
| V5-05 | ~~`ss` and `confirm_tag` come from `(k, nonce)`, and the tag does not depend on `ss`~~ | — | — | **WITHDRAWN.** The confirm tag is deleted (§3.5). `ss` from `(k, nonce)` is pinned by V5-05a below; the independence claim has nothing left to be independent of |
| V5-05a | `ss = SHA256("pq-stealth/pairwise-payment/v1" ‖ k_pairwise ‖ nonce)`, and the view tag follows from `ss` | `k`, counter 0 and counter 1 | two payment secrets, two view tags | deriving the tag from `(k, nonce)` directly, which is what the deleted confirm tag did — it produces a well-formed eight-byte value that no conforming sender emits |
| V5-06 | memo is **`view_tag(8)` and nothing else** | the payment above | exactly 8 bytes, and a round-trip parse | 24 bytes with a trailing counter, and 25 with a confirm tag as well — **the two shapes the reference implementations emit**; or a one-byte view tag |
| V5-07 | first contact is `epk` 33 in `ephemeralPubKey`, **`view_tag ‖ ct`** 1 096 in `metadata` | a new channel | 1 129 B | the fields swapped; **or `ct` alone with no tag, the shape the older references emit**. Note this shape is byte-identical to a schemeId 3 announcement (V3-08) — §6 declares the collision and recognition is by `schemeId` too |
| V5-08 | ~~a combined announcement MUST NOT be published, at 1 146 B~~ | — | — | **WITHDRAWN.** with V4-05. The combined announcement is the specified shape (§3.4). A fixture asserting it unrecognised would certify a scanner that rejects every conforming first contact |
| V5-09 | bad `epk` → skip, not error | 33 zero bytes; `0x02 ‖ 32×0xff`; a `0x05` tag | not mine ×3, no error | an error, which aborts the scan. The Rust accepted `0x05` and stored the channel; the TypeScript refused it |
| V5-10 | `ct` length ≠ 1 088 → skip | 1 087 B | not mine | an error |
| V5-11 | an address comparison is on the **20 address bytes**, never on a string form | a lowercase and an EIP-55 mixed-case form of one address | they compare equal | **string comparison** across the two forms, which matches nothing, silently. This row pins the comparison rule alone (§3.4): a paired-announcement half would have nothing to pair, since a first payment is one announcement. A wire-format test comparing the two forms of one address demonstrates the bug |
| V5-12 | a channel MUST NOT be retained without a **view-tag match on the first contact itself** | a first contact whose own tag does not verify at counter 0 | not retained | retained on decapsulation alone; **or gated on a paired memo's confirm tag, which gates on a field that is not on the wire** |
| V5-13 | a duplicate channel key MUST NOT be retained twice, **and the replay presents no payment** | the same first contact replayed | one channel, and no payment on the replay | two, and the list grows without bound even with the gate in place; or one channel retained but the replay credited as a second payment, which the retention count alone does not catch |
| V5-14 | ~~**every** memo bearing the first contact's `stealthAddress` is tried~~ | — | — | **WITHDRAWN.** with the requirement it pinned. The decoy attack it tested is unreachable once the pairing is transaction identity: an observer cannot add a log to someone else's transaction. Replaced by V5-14a |
| V5-15 | a scanning context cannot hold a sender-side channel | an attempt to place a channel the caller opened as payer into a scanning context | rejected **by construction** — it does not compile, or the API offers no such call | accepted and filtered at match time, which is the reference's shape and is breakable in a refactor with no test failing |
| V5-16 | a `schemeId` mismatch is a **skip** | an announcement under schemeId 2 to a recipient registered under 5, and one under 4 | not mine ×2, **no error** | an error — a permanent scan abort any stranger can trigger for one announcement's gas |
| V5-17 | ~~the accompanying memo is the memo in the first contact's own transaction~~ | — | — | **WITHDRAWN.** There is no accompanying memo and no pairing |
| V5-18 | **no vector — deliberately.** `CHANNEL_IDLE_SEND` and `CHANNEL_IDLE_SCAN` are a SHOULD NOT for the sender and a MAY for the scanner, so neither expiry nor retention is a conformance obligation and a fixture would pin a permission | — | — | a vector asserting a specific expiry block, which would make one of two conforming behaviours look non-conforming. **The memo-window half of this slot is empty too: those constants are withdrawn.** The slot stays empty until the idle constants are measured and the levels revisited |
| V5-19 | ~~the gating memo is **also** derived as a payment~~ | — | — | **SUPERSEDED by V4-03a and V4-03b**, which put the same requirement on the first contact. The requirement did not change; what satisfies it did |
| V5-06a | a scanner matches a memo by deriving the next `SCAN_LOOKAHEAD` counters, not by reading one | a channel at counter 3, and memos at counters 4, 5 and `4 + SCAN_LOOKAHEAD` | the first two matched; the third **not matched**, and no error | matching the third, which means the window was not applied and the scan is unbounded in the counter; or failing on it, which turns a sender's skip into an error a stranger could also cause |
| V5-14a | ~~a first contact whose transaction carries no verifying memo is discarded~~ | — | — | **SUPERSEDED by V4-03a.** Same disposition — discard, retain nothing — reached from the announcement's own bytes rather than from its transaction |
| V5-20 | a scanner that stops deriving for a **confirmed** channel can resume it without the seed-only path | a confirmed channel, idle past the scanner's own `CHANNEL_IDLE_SCAN`, then a memo | the channel resumes from its retained first-contact location and the payment is found | resumption only via `O(first-contacts × memos)` recovery, or no resumption at all — which is the invisible-payment path §3.6 now calls a latency cost |
| V5-21 | a watch delegation carries **one channel's `(k_pairwise, next counter)` and nothing else** — never the tracking key, never the spending point — and its report is §3.6's report in full: **the matched counter and the matched row's identity** | watch state for one channel whose window starts at counter 4, and a memo at counter 4 carrying its row's identity (the announced address, OPAQUE to the watcher — it enters no derivation) | the memo matched, and the report is the counter **and the row's identity echoed** — the watch type has no field for a DERIVED address or a key it must not hold, and the recipient performs §2.8's comparison locally against the identified row | including the tracking key, which un-scopes the delegation back to the whole graph; or the spending point, which names the recipient in their ERC-6538 registry entry; or a report without the row identity, which says a counter matched but not which public row to retrieve and verify |

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

## 6b. §4 — schemeId 6, wave 3

> The rows below are written from the post-quantum-spending document's §4.1–§4.5 — never
> from any implementation, and in particular **never from the Spirit parity KATs**, whose
> oracle is the authors' C and whose build reverts §4.1's mandatory per-one-time-key seed
> derivation; §4.2 states that incompatibility in full. The documented likeliest wrong
> answer throughout is the upstream reference's own layout: `opk_ds ‖ ct` with `rho` on
> the wire and no view tag.
>
> **The generatable rows below are runner-executed** — the rung's implementation landed
> after they were committed, so a pass is a cross-implementation agreement, and the golden
> count in the runner's test rose by exactly their number. **What cannot
> have a row:** anything requiring §4.6's mapping — the address rows stay in `V1-08`'s
> class of named absences until that decision lands. And two expectations need lattice
> arithmetic derived from the prose (`ExpandA`, NTT, `Power2Round`) that this generator
> does not have:
> **V6-17** and **V6-18** are specified and ungenerated, with the reason stated — `V6-03`'s
> discipline — rather than filled from an implementation, which would make the vectors a
> regression suite for one codebase, the failure the front door names.

| id | claim | given | expect | wrong |
|---|---|---|---|---|
| V6-06 | §4.1 — the keygen seed is `dsa_seed(32) ‖ kem_seed(64)` = 96 B, and an implementation MUST reject any other length | seeds of 95, 96 and 97 bytes | 95 and 97 rejected; 96 accepted (its expected keys are `V6-17`) | accepting either neighbour; or the 192-byte `rho ‖ mkgen_seed ‖ kem_seed` form §5 records as wrong twice over |
| V6-07 | §4.1 — an implementation MUST reject a keygen where **any 32-byte window** of `kem_seed` equals `dsa_seed` — the delegated object is 64 B, so 33 windows | one `dsa_seed`, and `kem_seed`s with it planted at offsets 0, 16 and 32, plus a clean control | the three planted rejected; the control accepted | scanning §2.9's 65 offsets, which belong to a 96-byte delegated object this rung does not have; or checking the two aligned halves only, which misses offset 16 |
| V6-08 | §4.1 — `rho' ‖ rhoprime ‖ key = SHAKE256(dsa_seed, 128)` at offsets 0, 32, 96: `rho'` MUST be squeezed and discarded, and `rhoprime` and `key` MUST sit at offsets 32 and 96 of the **same** stream | one `dsa_seed` | the 128-byte stream, `rhoprime` = bytes 32..96, `key` = bytes 96..128 | expanding only 96 bytes and reading from offset 0 — the computed value is committed, and it yields a different masking vector and signatures that verify under nothing |
| V6-09 | §4 deviation 1 and §4.2 — `CRS_V1 = keccak256("pq-stealth/crs/v1")`, a decoder reconstructs `pk_ds = CRS_V1 ‖ t1`, and `rho` is not on the wire | the string literal | the 32 bytes §4 states, re-derived by this generator's own keccak | `sha3_256` of the same literal — NIST padding, a plausible 32 bytes no Ethereum node reproduces; or SHAKE256 of it; both computed so a runner can tell which mistake was made |
| V6-10 | §4.2 — decoding MUST reject any length that is not the one its category names, and a decoder MUST accept all three | lengths 4 128, 5 600 and 7 072; their off-by-one neighbours; and this document's other meta-addresses at 1 217 and 1 250 B | the three accepted, with category attribution 2 / 3 / 5; every other length rejected | accepting the `t1 ‖ ek` totals, which omit `t0` and make every payment unfindable; or a `rho`-carrying form 32 B longer |
| V6-11 | §4.2 — the meta-address is `t1 ‖ t0 ‖ ek`: `t0` MUST be published, and the field offsets are `k·320` and `k·320 + k·416` | the category table, `k = 4 / 6 / 8` | per-category offsets, with `ek` the final 1 184 B in each | omitting `t0` — `OPKGen` and `Track` form `t'` from full-precision `t`, so a sender holding `t1` alone pays an address nobody can find |
| V6-12 | §4.3 — the announcement is `t1_ot` in `ephemeralPubKey` (`k·320` B) and `view_tag ‖ ct` in `metadata` (1 096 B), and MUST NOT carry `rho`; payloads 2 376 / 3 016 / 3 656 B | the wire table | field lengths and totals per category; `metadata` = 8 + 1 088 | the reference's `opk_ds ‖ ct` with `rho` and no view tag — 24 B larger per category, and its first 32 bytes are a recipient tag a `memcmp` links with no key material |
| V6-13 | §4.3 — `view_tag = SHA256("pq-stealth/view-tag/v1" ‖ ss)[0..8]`, and it sits **first** in `metadata` | one `ss` | the eight bytes, computed | a one-byte tag — the pre-widening width, which leaves the most expensive per-announcement work in the ladder running on one foreign announcement in 256; or SHAKE256 in place of SHA256; both computed |
| V6-14 | §4.4 — the sender chain is deterministic from `encap_seed`: `(ct, ss) = ML-KEM-768.Encaps(ek, encap_seed)`, `view_tag` from `ss` | an `ek` from a fixed `(d, z)`, one `encap_seed` | `ct` (1 088 B), `ss` and `view_tag`, all computed | drawing fresh randomness instead of the derandomised form, which makes announcements irreproducible from the seed record and unauditable against §5's stream |
| V6-15 | §4.4 with §5 — the announce seed is drawn per §5 under each of schemeId 6's **three canonical rung names**, and MUST NOT be reused; distinct indices give distinct seeds | one `master`, the three rung names, indices 0 and 1 | six distinct 32-byte seeds, the three per-rung streams pairwise disjoint | sharing one stream across the three levels — §5 requires independence per (`schemeId`, `rung`) pair, and the `schemeId` alone does not separate them because all three levels share it |
| V6-16 | §4.5 — the skip ladder: wrong `metadata` length, wrong-category `ephemeralPubKey` length, view-tag mismatch — each is "not ours", and every negative outcome MUST be a skip, never an error | three announcements: `metadata` of 1 095 B; `ephemeralPubKey` of 1 920 B against a category-2 key; a valid shape whose tag does not match | each skipped, no error on any path | an error on any of the three — `announce()` is permissionless, so an error path is a denial of service a stranger can trigger; or running `Track` at the wrong category, which the second line of §4.5's ladder exists to prevent |
| V6-17 | §4.1's accept half, in bytes: the meta-address a conforming keygen derives from an accepted 96-byte seed | a 96-byte seed | the `t1 ‖ t0 ‖ ek` bytes, derived from the prose | filling the expectation from an implementation — the bytes require `ExpandA`, NTT and `Power2Round` derived independently, which this generator does not have; recorded ungenerated with the reason, `V6-03`'s discipline |
| V6-18 | §4.5's retain half: a conforming announcement for a known key is retained — `Decaps`, tag match, `Track` true | a meta-address and an announcement derived from one `encap_seed` | retained | same reason as `V6-17`: the positive path needs spec-derived lattice arithmetic; a fixture filled from the implementation under test, or from the parity KATs — whose build is non-conforming by construction — would pin the wrong oracle |

**Every `provisional` row, and why.** The fixtures are the authority — `provisional: true` in the
JSON — and the reason is one string in `tools/gen_vectors.py` so it cannot drift between rows:

| row | why it is provisional |
|---|---|
| `V3-05`, `V3-06` | §2.9's domain separator and combiner are new in this document |
| `V4-01`, `V4-02`, `V5-02`, `V5-05a` | §3's channel-key and payment separators are new in this document |
| `V5-06a` | `SCAN_LOOKAHEAD` is the **fixture's choice, not the specification's** — §3.6 leaves the value to ecosystem agreement, and this row is what carries the chosen number |
| `V6-01`, `V6-02`, `V6-03`, `V6-04`, `V6-05` | §5's seed derivations are new in this document |
| `V6-06`, `V6-07`, `V6-08`, `V6-09`, `V6-10`, `V6-11`, `V6-12`, `V6-13`, `V6-14`, `V6-15`, `V6-16`, `V6-17`, `V6-18` | §4's wire layout, CRS and derivation constants are new in this document |

In every case the claim is that **no outside implementation has adopted the constant**.
Waves 1 and 2 have the same two internal witnesses: this project's implementation produces
these bytes, and a blinded re-derivation from the prose alone agreed on them — wave 2's
covering every byte-valued row, with the three KEM-dependent rows re-derived against
supplied NIST-oracled KEM outputs. **Wave 3's rows have TWO internal witnesses** — this
generator's prose-derived computation, and the rung implementation that executes the
generatable rows (written after the fixtures were committed, so agreeing but not blinded)
— plus an ACVP-accepted ML-KEM where a row carries KEM output; the blinded re-derivation
has not run over this wave, and the fixtures' own `provisional_because` says so. No
witness is an outside party, so the constants remain proposals.

**V6-03 cannot be written without a conformance hook, and that is the same gap §1 has.**
Finding a `master` and index whose derived seed is an
invalid secp256k1 scalar is a ~2⁻¹²⁸ search, so the vector is unconstructible from the public
interface — exactly the problem this plan already names for §1's scalar reduction, where the
existing test became a tautology for want of a chosen input. **The same one-sentence spec
change fixes both**: the retry paths MUST be testable with a chosen seed. Until that lands,
**V6-03** is specified and ungenerated, and saying so is better than shipping a fixture that
exercises nothing.

## 7. What no fixture can check

Stated so the vector set is not read as covering more than it does. Each of these needs
the harness:

| | why a fixture cannot reach it |
|---|---|
| keygen determinism *across processes* | a fixture pins one output; only a harness runs it twice |
| announce-seed non-reuse | a property of a sequence of calls, not of one input |
| the master-recovery hazard | an assertion about what an implementation must **not** expose |
| counter exhaustion | reachable only by RESUMING at the top of the counter space — no payment sequence gets there — and the boundary is a unit-tested reservation, not a fixture's input/output pair: `u128::MAX` is the exhaustion sentinel, refused before deriving on the sender side and never derived into a window on the scanner's |
| sender-side channels never matched | a requirement on **state shape**, so a fixture cannot reach it at all — V5-15 checks the API's shape, not an input/output pair, and the persistence path that crosses the shapes is role-tagged (a cross-role restore fails at its first byte, unit-tested) |
| cross-channel tag-collision resolution | constructing two channels whose windows share a tag is a 2³² birthday search — no honest fixture reaches it. The resolution rule is a PURE function in the reference (`choose_candidate`) and its unit tests are the seam: one candidate untouched, the address-matching one among several, none on a lying multi-way tie |
| recovery cost `O(fc × memos)` | a complexity claim |
| constant-time behaviour | unspecified everywhere in the document |

## 7a. Coverage, and the four counts

**This target replaced a number that had no harness.** A session record quoted "82 of
290 requirements pinned". No tool produced it, nothing recorded how it was derived, and it
conflated RFC 2119 keywords with requirement sentences. By this project's own rule a
measurement whose generator does not exist is worse than an absent one, so the figure is
withdrawn and this section is generated instead.

**The count depends on what you are counting, and quoting the wrong one is a real
defect class: 61 is right as a count of rows and wrong as a count of *emittable*
fixtures, and a document quoting 59 quotes a number that matches no count of anything.** The four counts below are all true
at once:

| count | what it is | use it for |
|---|---|---|
| **enumerated** | every distinct `V`-id this plan names, including ids that exist only as a named absence in prose | how much of the surface the plan has *considered* |
| **rows** | ids appearing as a table row | reading this document |
| **slots** | rows minus deliberately empty rows | how many fixtures the plan *reserves* |
| **generatable** | slots minus ids marked *specified and ungenerated* | **the only count a generator's acceptance criterion may use** |

**A tool gets this wrong exactly as easily as a hand does, which is the point.** A row
regex that misses the four letter-suffixed ids (`V3-02a`, `V3-06a`, `V3-06b`, `V3-08a`)
reports 57 rows — a fifth wrong number. A harness is
worth more than a hand-count because it can be *checked*, not because it is right first
time.

the coverage gate in the authoring repository computes all four from this file's own prose — a new
deliberate absence or a newly generatable row moves them with no edit to the tool — and
fails the guard if any document states a number that is none of them, or if a generator criterion
quotes anything but `generatable`.

<!-- COVERAGE TABLE -- generated, do not edit by hand -->

| section | document | levelled keywords | vector rows |
|---|---|---|---|
| ERC-WWWW: Post-Quantum Stealth Addresses — schemeIds 4 and 5 (pairwise channel) | channel | 0 | — |
| Abstract | channel | 0 | — |
| Motivation | channel | 0 | — |
| Dependencies | channel | 0 | — |
| Specification | channel | 5 | — |
| §3 3. schemeIds 4 and 5 — pairwise channel | channel | 0 | 8 |
| §3.1 3.1 Keys and seeds | channel | 4 | 0 |
| §3.2 3.2 Meta-address encoding | channel | 3 | 0 |
| §3.3 3.3 First contact, and the channel key | channel | 8 | 0 |
| §3.4 3.4 Wire mapping — normative | channel | 10 | 0 |
| §3.5 3.5 Per payment | channel | 14 | 0 |
| §3.6 3.6 Scanner: the view-tag gate, and channel retention | channel | 42 | 0 |
| §3.7 3.7 Recipient | channel | 1 | 0 |
| §3.8 3.8 Recovery from the seed alone | channel | 9 | 0 |
| §3.9 3.9 What is an error and what is a skip | channel | 1 | 0 |
| §3.10 3.10 What this section does not specify | channel | 3 | 0 |
| §3.11 3.11 Prior art for the pairwise channel | channel | 1 | 0 |
| §3.12 3.12 schemeId 5 — the hybrid variant | channel | 13 | 24 |
| Rationale | channel | 4 | — |
| Backwards Compatibility | channel | 0 | — |
| Test Cases | channel | 0 | — |
| Reference implementation | channel | 0 | — |
| Security Considerations | channel | 0 | — |
| Copyright | channel | 0 | — |
| Open before submission | channel | 1 | — |
| ERC-XXXX: Post-Quantum Stealth Address Schemes (schemeIds 2 to 6) | common | 3 | — |
| Abstract | common | 0 | — |
| Motivation | common | 0 | — |
| The announcement layer and the spending layer have different clocks | common | 0 | — |
| What this does not fix, stated up front | common | 0 | — |
| Specification | common | 5 | — |
| §1 1. Common definitions | common | 16 | 7 |
| §1.1 1.1 The hybrid combiner | common | 13 | 0 |
| §2 2. schemeIds 2 and 3 — specified separately | common | 0 | 0 |
| §3 3. schemeIds 4 and 5 — specified separately | common | 0 | 0 |
| §4 4. Post-quantum spending — specified separately | common | 3 | 0 |
| §5 5. Sender entropy — normative | common | 26 | 5 |
| §6 6. Wire formats and registry | common | 22 | 0 |
| §7 7. Cost | common | 4 | 0 |
| schemeId 6 verification | common | 8 | — |
| §8 8. Operational requirements — normative | common | 16 | 0 |
| Rationale | common | 3 | — |
| Backwards Compatibility | common | 3 | — |
| Test Cases | common | 3 | — |
| Reference implementation | common | 1 | — |
| Security Considerations | common | 0 | — |
| §9 9. Security considerations | common | 17 | 0 |
| Copyright | common | 0 | — |
| Open before submission | common | 3 | — |
| Post-quantum spending — schemeId 6 | pq-spending | 1 | — |
| §4 4. schemeId 6 — post-quantum spending | pq-spending | 8 | 13 |
| §4.1 4.1 Keys and seeds | pq-spending | 5 | 0 |
| §4.2 4.2 Meta-address and registration | pq-spending | 7 | 0 |
| §4.3 4.3 Announcement and wire mapping | pq-spending | 3 | 0 |
| §4.4 4.4 Sender | pq-spending | 4 | 0 |
| §4.5 4.5 Scanner | pq-spending | 3 | 0 |
| §4.6 4.6 The address mapping — an open decision, and the one that blocks emission | pq-spending | 8 | 0 |
| §4.7 4.7 `OPKGen`, `Track` and `OSKGen` — defined | pq-spending | 13 | 0 |
| §4.8 4.8 Recipient and spending | pq-spending | 5 | 0 |
| ERC-ZZZZ: Post-Quantum Stealth Addresses — schemeIds 2 and 3 (per-payment) | per-payment | 0 | — |
| Abstract | per-payment | 0 | — |
| Motivation | per-payment | 0 | — |
| Dependencies | per-payment | 1 | — |
| Specification | per-payment | 5 | — |
| §2 2. schemeIds 2 and 3 — per-payment | per-payment | 0 | 13 |
| §2.1 2.1 Keys and seeds | per-payment | 6 | 0 |
| §2.2 2.2 Meta-address encoding | per-payment | 7 | 0 |
| §2.3 2.3 Registration | per-payment | 4 | 0 |
| §2.4 2.4 Sender | per-payment | 6 | 0 |
| §2.5 2.5 Scanner | per-payment | 8 | 0 |
| §2.6 2.6 Recipient | per-payment | 12 | 0 |
| §2.7 2.7 What is an error and what is a skip | per-payment | 1 | 0 |
| §2.8 2.8 What this section does not specify | per-payment | 9 | 0 |
| §2.9 2.9 schemeId 3 — the hybrid variant | per-payment | 12 | 12 |
| Rationale | per-payment | 2 | — |
| Backwards Compatibility | per-payment | 0 | — |
| Test Cases | per-payment | 0 | — |
| Reference implementation | per-payment | 0 | — |
| Security Considerations | per-payment | 0 | — |
| Copyright | per-payment | 0 | — |
| Open before submission | per-payment | 3 | — |
| **total** | 4 documents | **398** | **82** |

**Read this table with its two limits in mind — each is a way to misquote it.**
The middle column counts RFC 2119 *keywords*, not requirement
sentences -- one sentence can carry two -- so it is an upper bound and MUST NOT be
quoted as a requirement count. And a vector is attributed to a section by the group
heading it sits under, so a zero in the right-hand column means *no group targets this
section*, not *untested*: the wire-format section's rules are exercised by the
per-scheme metadata vectors, and the cost section is not fixture-testable at all.
A dash means the section carries no number, so no vector group can target it —
distinct from a numbered section showing zero. And a group aimed at a parent
section exercises requirements written in its subsections, so the two columns are
comparable per *group* rather than row by row: §3's group tests text stated across
§3.1 to §3.11, which appear here as their own rows. (No count is written into this
note on purpose -- a hand-written number inside generated output is the defect this
whole tool exists to remove.)

Generated by a coverage gate the authoring repository's guard runs on every pass, from this file's own prose. Every count below is derived rather than typed.
<!-- END COVERAGE TABLE -->

## 8. Deliverables, in order

1. `tools/gen_vectors.py` — standalone, `hashlib` plus one secp256k1 library, **imports
   nothing from this repository.** Emits one JSON file per section plus a manifest with a
   sha256 per file.
2. `vectors/*.json` — the sets above, committed.
3. a directory note beside them, where a tree carries one — what each file pins, and the
   tier-1 vendoring pointer.
4. **The author reads the vectors.** This is the gate; the code comes after.
5. a fixture gate in the authoring repository — a runner an implementation calls with four function
   pointers, so a third party can check conformance without reading any of our code.

**One spec change this plan surfaced, still not applied:** §1 needs to say that the
reduction MUST be testable with a chosen `base`. §2.9's domain separator was the other; the
combiner it belongs to is settled, but the string itself still has no
implementation to agree with, so V3-05, V3-06, V6-01 and V6-03 keep the `provisional` flag
until the author confirms it.

**Every row here tracks the decided design, and the failure mode this file is most
exposed to is a fixture asserting superseded behaviour.** The worst form is a row like a
V3-02 that pins as conformant a per-half delegation scan the specification rejects as a
security defect — a fixture that would certify the bug and pass a second implementer who
shipped it. That risk argues for regenerating the plan from the draft rather than
maintaining it alongside, and it is why every row states its `wrong` alongside its
`given`/`expect`: a stale row then contradicts the specification visibly rather than
silently.
