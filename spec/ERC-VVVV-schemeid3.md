# ERC-VVVV: Post-Quantum Stealth Addresses — schemeId 3

## Abstract

[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) defines stealth addresses and a registry
of `schemeId`s, of which only `schemeId 1` (secp256k1) is specified. This ERC specifies one
further scheme, **schemeId 3**, which makes the **announcement layer** post-quantum.

| | schemeId 3 |
|---|---|
| announcement secret | ML-KEM-768 **combined with a secp256k1 ECDH secret** |
| announcement | 1 122 B, one encapsulation and one ephemeral key per payment |
| meta-address | 1 250 B, registered once via ERC-6538 |
| spending | secp256k1 ECDSA |
| account | a plain EOA — no batching account, no ERC-4337, no EIP-7702 |

This needs no protocol change, no new contract, and nothing of the sending account. 
The ECDH half is a migration hedge against a defect in an ML-KEM implementation, and it is
NOT post-quantum protection. Spending is secp256k1, so a quantum adversary ends this scheme
whatever its announcement layer does. 
schemeId 3 has a reference implementation against this document, in `crates/per-payment`.

## Motivation

### The announcement layer and the spending layer have different clocks

A stealth-address announcement is public and permanent. Anything an observer records today
can be broken later by a cryptographically relevant quantum computer, and the privacy loss is
**retroactive** — harvest now, deanonymise later. 
That asymmetry says the announcement layer is the urgent one, and it can be upgraded without
touching the spending path. ERC-5564's `Announcement` and ERC-6538's `registerKeys` take
unbounded `bytes`, so nothing needs redeploying.

This ERC closes that retroactive hole. 

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described
in RFC 2119.

### 1. Common definitions

`ML-KEM-768` is as specified in FIPS 203, **unmodified in its algorithms and in its
parameters** — and the **derandomised internal algorithms** are the ones this document
requires, not the public interface.

Two requirements in this document are only satisfiable through the internal entry points:
encapsulation MUST be deterministic in `m` (§2.4), and §5 requires `m` to be **derived**
rather than sampled; and the decapsulation key MUST be the 64-byte `(d, z)` seed rather than
the expanded form. FIPS 203's `ML-KEM.Encaps` and `ML-KEM.KeyGen` draw their own randomness
and return an expanded `dk`, so an implementation MUST use **`ML-KEM.Encaps_internal(ek, m)`**
and **`ML-KEM.KeyGen_internal(d, z)`** — Algorithms 17 and 16. **Decapsulation is NOT
constrained: `ML-KEM.Decaps` and `ML-KEM.Decaps_internal` are both permitted.**

A recipient or a delegated
scanner MUST recompute `ek` from its `(d, z)` seed and compare it against the `ek` in the
registered meta-address, at least once before scanning — **and the same requirement covers
the viewing EC half: the point derived from the delegated viewing scalar MUST be compared
against the registered `viewing_pk_ec` in the same pass.** 

A decapsulation key MUST be represented as the 64-byte `(d, z)` seed. This is the KEM half of
the **tracking key** delegated to a scanner.

The stealth derivation is ERC-5564's, unchanged:

```
stealth_pk = spending_pk + H(ss)·G
stealth_sk = spending_sk + H(ss)
H(ss)      = SHA256("pq-stealth/offset/v1" ‖ ss), reduced to a valid scalar
view_tag   = SHA256("pq-stealth/view-tag/v1" ‖ ss)[0]                     1 B
```

Scalar reduction MUST use one shared counter-based procedure for sender and recipient. If the
two diverge on the rare retry path, funds become unspendable — so the procedure is given in
full rather than described:

```
base = SHA256("pq-stealth/offset/v1" ‖ ss)
for counter in 0, 1, 2, … 256:
    candidate = base                                       if counter == 0
              = SHA256("pq-stealth/offset/v1" ‖ base ‖ u8(counter))   otherwise
    if 0 < candidate < n_secp256k1:  H(ss) = candidate; stop
fail
```

Convention: **Every 32-byte digest above MUST be interpreted as a 256-bit unsigned integer in big-endian
order (uNbe)**, most significant byte first — both for the comparison `0 < candidate < n_secp256k1`
and for the scalar that results. `u8(counter)` is a single byte, and an implementation MUST fail rather than continue past
`counter = 256`. Both sides run this identical procedure. **The view tag is still one byte**.

#### 1.1 The hybrid combiner

schemeId 3 derives its **per-payment secret** by combining an ECDH shared secret with the
ML-KEM shared secret (§2.4). The construction is given here once.

```
hybrid_combine(DS, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
    = SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek)               32 B
```

The caller supplies the domain separator `DS` and names the output; §2.4 gives this scheme's
value, `"pq-stealth/hybrid-payment/v1"`, and names the output `ss`.
1. **`ss_ec` MUST be the x-coordinate alone**, 32 bytes, big-endian.
2. **The domain separator is the FIRST input, then the six fields.** An implementation MUST
   NOT append it, and MUST NOT length-prefix it.
3. **The output MUST be the full 32-byte digest**, truncated nowhere, and the input order
   MUST be exactly `DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek`.
4. **Explicitly**: `epk` and
   `viewing_pk_ec` are **33-byte SEC1-compressed** points; `ct` is the 1 088 announcement bytes; `ek` is the 1 184
   meta-address bytes; and `ss_ec` is the 32-byte x-coordinate per item 1.
5. **`epk` MUST be bound into the KDF.** Without it, flipping the compressed parity byte yields the
same ECDH x-coordinate and therefore the same payment secret.

**The IKM is the combiner NIST SP 800-227 puts forward**
A broken ML-KEM implementation is exactly the failure this scheme hedges, so a combiner without
that preservation property hedges less than it appears to. The combiner NIST puts forward
instead is `H(K1, K2, c1, c2, ek1, ek2, domain_sep)`, and the **inputs** map onto it one for
one:

| NIST input | here | why |
|---|---|---|
| `K1`, `K2` | `ss_ec`, `ss_pq` | the two shared secrets |
| `c1` | `epk` | the ephemeral public key **is** the DH ciphertext |
| `c2` | `ct` | the input SP 800-227's argument turns on |
| `ek1` | `viewing_pk_ec` | binds the secret to the recipient's identity |
| `ek2` | `ek` | redundant and added for conformance |
| `domain_sep` | the domain separator, the **first** hash input | already distinct per scheme |

**SHA3-256 rather than keccak256**, matching X-Wing and FIPS 202.
**Every added byte is already on the wire or in the registry, so the announcement does not
grow and gas is unchanged.**

### 2. schemeId 3 — per payment, hybrid

One encapsulation and one ephemeral key per payment. The announcement is an ephemeral public
key plus a one-byte view tag and a KEM ciphertext; spending stays secp256k1 ECDSA on an
ordinary EOA, so it needs no new verifier and no consensus change. Each announcement carries
a fresh encapsulation and a fresh ephemeral key, so two payments do not share those values.
That is key separation and  a later compromise of the recipient's
long-term tracking key still opens every past ciphertext.

```
sender    : esk, epk    ← a fresh ephemeral secp256k1 keypair
            (ct, ss_pq) ← ML-KEM-768.Encaps(ek, encap_seed)
            ss          ← hybrid_combine(…, ECDH(esk, viewing_pk_ec).x, ss_pq, …)
            publish (epk, view_tag(ss) ‖ ct); pay address(stealth_pk)
scanner   : ss_ec ← ECDH(viewing_ec, epk); ss_pq ← Decaps(dk, ct)
            ss ← the identical hybrid_combine call; check view_tag; recompute stealth_pk
recipient : stealth_sk = spending_sk + H(ss) mod n
```

#### 2.1 Keys and seeds

The keygen seed is `spending_seed(32) ‖ viewing_ec_seed(32) ‖ kem_seed(64)` = **128 bytes**.
An implementation MUST reject any other length rather than padding or truncating.

- `spending_seed` MUST be a valid secp256k1 scalar: `0 < spending_seed < n`, read big-endian
  per §1. It is the master spending key.
- `viewing_ec_seed` MUST be a valid secp256k1 scalar per §1. It is the viewing scalar
  `viewing_ec`, and it is **delegated**.
- `kem_seed` is ML-KEM's `(d, z)` pair as defined in §1, and becomes the decapsulation key
  verbatim. It is **delegated**.

**An implementation MUST reject a keygen whose spending scalar appears anywhere inside the
material that gets delegated — and the delegated material is the 96-byte concatenation
`viewing_ec ‖ dk` taken as a whole, not its two halves separately.** The test is a 32-byte
window scan at every one of the 65 offsets: **an implementation MUST scan the 96-byte
concatenation `viewing_ec ‖ dk` at all 65 offsets, and MUST reject a keygen where any 32-byte
window of it equals `spending_seed`.**

```
if any 32-byte window of (viewing_ec ‖ dk) equals spending_seed:  reject
```

The reason is specific to this scheme. The tracking key **is** those 96 bytes, so
`spending_seed` appearing anywhere inside them places the master spending key verbatim inside
the object handed to a scanning service, and that service can then spend. This is
reproducible end to end against a real payment. A prefix comparison is insufficient because
the scalar at any offset is the same defect.

**Scanning the two halves separately covers 34 offsets, misses the 31 that straddle the
boundary, and MUST NOT be done.** Those 31 positions place the spending seed verbatim in
bytes handed to a scanning service and pass a per-half check.

Three outputs, with three different dispositions:

| output | contents | size | disposition |
|---|---|---|---|
| meta-address | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` | 1 250 B | **published** via ERC-6538 |
| master | `spending_sk` | 32 B | never leaves the owner |
| tracking | `viewing_ec ‖ dk` | **96 B**, two secrets | **MAY be delegated** to a scanner |

Keygen MUST be deterministic in the seed: the same 128 bytes MUST produce the same three
outputs. Without that, conformance vectors are impossible.

#### 2.2 Meta-address encoding

```
meta = spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)              1 250 B
```

- `spending_pk` and `viewing_pk_ec` MUST each be the SEC1 **compressed** encoding, 33 bytes.
- `ek` MUST be the 1 184-byte ML-KEM-768 encapsulation key of §1.

We MAY want to constrain the SEC1 **compressed** encoding with a leading tag byte of **`0x02` or `0x03` only**. An implementation then MUST reject any
  other encoding of the same point, and MUST use **one decoder** for both.

Decoding MUST reject a length other than 1 250, and MUST validate **both** points as curve
points **before** the meta-address is used for anything. `ek` is validated by the KEM on
first use; an implementation MUST NOT assume a well-formed length implies a well-formed key.

#### 2.3 Registration

A recipient MUST register the encoded meta-address via ERC-6538 `registerKeys` with
`schemeId` 3. **A recipient MAY register several `schemeId`s, per §6**, and a scanner MUST
use the set the recipient registered and MUST NOT process an announcement carrying any
`schemeId` outside it.

#### 2.4 Sender

The announce seed is **64 bytes**, `ephemeral_seed(32) ‖ encap_seed(32)`. It MUST be drawn
per §5 and MUST NOT be reused; §5 states why binding `schemeId` alone is insufficient.

```
esk         = ephemeral_seed                    a valid secp256k1 scalar per §1
epk         = SEC1-compressed(esk · G)                                     33 B
ss_ec       = x-coordinate of ECDH(esk, viewing_pk_ec)                     32 B
(ct, ss_pq) = ML-KEM-768.Encaps(ek, encap_seed)                 1 088 B / 32 B
ss          = hybrid_combine("pq-stealth/hybrid-payment/v1",
                              ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)    32 B
offset      = H(ss)                              per §1, big-endian, counter-reduced
stealth_pk  = spending_pk + offset·G
address     = keccak256(uncompressed(stealth_pk) without its 0x04 prefix)[12..32]
```

> **The domain separator above is implemented and pinned.** `crates/per-payment` uses it and
> `vectors/section-2_9.json` fixes its bytes, so it is a specified constant rather than a
> proposal.

Encapsulation MUST be deterministic in `encap_seed`, so that a vector fixing `(ek, m)` fixes
`ct` and `ss_pq`. The sender then:

1. publishes the announcement of §5 — `epk` in `ephemeralPubKey`, the 1 089 bytes
   `view_tag(ss) ‖ ct` in `metadata`; and
2. pays `address`.

**The `stealthAddress` field of the announcement MUST be the address derived above, and a
scanner MUST compare the address it derives against it.** A sender that announces one address
and pays another has made a payment its recipient cannot find.

The comparison is **local and exact**: the announcement carries the address, so a scanner needs
no chain query to perform it, and 160 bits decide the question outright. That is what allows
§1's view tag to be **one byte**. ML-KEM rejects implicitly — a foreign ciphertext yields a
pseudorandom secret and no error — so something other than the KEM has to decide whether an
announcement is ours; the announced address is that something, and the tag is a prefilter in
front of it rather than the decision itself. A mismatch is a **skip** and not an error (§2.7):
`announce()` is permissionless, so an error path here would be a denial of service.

The sender learns `stealth_pk` but never `stealth_sk`, and MUST NOT be able to: the
recipient's `spending_sk` is the other addend.

#### 2.5 Scanner

Given the tracking key, the meta-address, and an announcement already classified as schemeId
3 per §6:

```
ss_ec ← x-coordinate of ECDH(viewing_ec, epk)
ss_pq ← Decaps(dk, ct)
ss    ← the identical hybrid_combine call of §2.4
if view_tag(ss) ≠ announcement.metadata[0]:  not ours, skip
stealth_pk ← spending_pk + H(ss)·G
if address(stealth_pk) ≠ announcement.stealthAddress:  not ours, skip
```

As the view tag is a
function of `ss`, it cannot be computed before decapsulation and the ECDH. This scheme
therefore has **no prefilter ahead of the KEM**: one ECDH and one ML-KEM-768 decapsulation are
paid on **every** announcement, on input that anyone can publish, and that is the floor.

What the tag filters is the work *after* it. At one byte it admits one foreign announcement in
256, so the scalar multiplication and the address derivation are paid on 1 in 256 rather than
on all — the expected per-announcement cost is one ECDH, one decapsulation, and 1/256 of a
scalar multiplication. **A scanning service MUST be sized on the decapsulation**, which is the
term the tag cannot reduce; sizing on the scalar multiplication as though it were paid per
announcement overstates that term by a factor of 256.

#### 2.6 Recipient

```
stealth_sk = (spending_sk + H(ss)) mod n
```

A wallet SHOULD verify that the derived key controls the derived address — as a
key-to-address relation, not merely that bytes were produced — before presenting the payment
as spendable.

**A one-time key and its `ss` together recover the master spending key**, since
`spending_sk = stealth_sk − H(ss) mod n`. Implementations MUST NOT disclose both for the same
payment, and MUST NOT treat a one-time key as low-value on the grounds that it controls one
address. In particular a scanning service already holds every `ss`, so handing it any
one-time key hands it the master. §7 carries the general treatment.

#### 2.7 What is an error and what is a skip

| condition | scanner behaviour |
|---|---|
| `schemeId` ≠ registered | skip |
| field lengths match no §6 row | skip |
| `epk` malformed or not a curve point | skip |
| `ct` malformed, `ek` malformed | skip |
| view-tag mismatch | skip |
| announced `stealthAddress` ≠ the derived address | skip |
| decapsulation "fails" | **cannot happen** — ML-KEM rejects implicitly |
| keygen seed not 128 bytes | error, at keygen |
| `spending_seed` or `viewing_ec_seed` not a valid scalar | error, at keygen |
| spending scalar found in delegated material | error, at keygen |
| meta-address length ≠ 1 250, or either point not a point | error, at decode |

### 5. Wire formats and registry

Announcements MUST use ERC-5564's `announce()` unchanged. Meta-addresses MUST be registered
via ERC-6538 `registerKeys` with the matching `schemeId`.

**Field order is normative**, and a schemeId 3 announcement has two fields in `metadata`, so
the wrong order is the same length as the right one and the
length-based skip rule below does not bind it: a scanner reading the fields in the wrong
order sees nothing wrong about the announcement.

1. **The view tag MUST be the first byte of `metadata`**, at `metadata[0]`, with no
   exception.
2. **`metadata` MUST be exactly `view_tag ‖ ct`, in that order**, and an implementation MUST
   NOT reorder the fields.
3. **`ephemeralPubKey` MUST carry exactly `epk`**, and an implementation MUST NOT swap the
   two ERC-5564 fields. Note this cannot be inferred from lengths: **1 088 bytes of ML-KEM
   ciphertext identify no `schemeId` by position**, since a scheme is free to place them in
   either ERC-5564 field and registered schemes differ on which. Recognition is by `schemeId`
   together with the field lengths, never by where the ciphertext sits.
4. **Every multi-byte integer on the wire is big-endian.** No such integer occurs in a
   schemeId 3 announcement. The rule stands for a future revision that adds one.
   
### 6. Cost

Announcement cost, measured as **real standalone transactions** against the real ERC-5564
interface on anvil (`--hardfork prague`), with `gasUsed` read off the receipt. These are
**total transaction gas** — the 21 000 intrinsic and every calldata byte included — so no
convention needs stating. The generator ships beside the figures, at
`harness/announcement/measure.py`, and reads its field lengths from `tools/derive_sizes.py`
rather than retyping them; the receipts are committed at
`harness/announcement/measured.json`, and `tools/check_measured.py` re-derives every one of
them from the EIP-7623 rule with no node.

| schemeId | payload | calldata | execution | gas | floor binds | vs classical |
|---|---|---|---|---|---|---|
| 1 (classical, ERC-5564's own) | 34 B | 292 B | 5 143 | **28 067** | no | 1.00× |
| **3** | **1 122 B** | **1 380 B** | **14 269** | **69 360** | YES | **2.47×** |

> **Both rows are measured.** The measurement regime is withdrawal-not-adjustment: when a
> payload moves (a tag changes width, a field leaves the wire), every affected figure is
> withdrawn and re-measured rather than adjusted by the known byte delta, because an adjusted
> figure has no generator. Every figure in this table was re-measured when the view tag
> narrowed from eight bytes to one.
>
> **The calldata column did not move with the payload, and that is not an error.** ABI
> encoding pads `metadata` to whole 32-byte words, and 1 089 bytes and 1 096 bytes both
> occupy 35 of them. The seven bytes did not leave the calldata; they became zero padding,
> which EIP-7623 prices at 1 token against 4 — so the narrowing is worth 21 tokens, or 210
> gas, and not the 280 a reader computing 7 × 4 × 10 would expect.
>
**The EIP-7623 calldata floor binds**, so execution gas is not charged at all — the cost is
data availability, and optimising the announcer buys nothing.

**Registration is priced against the canonical registry itself.** Every row above is an
`announce()` call; a recipient also makes a one-time ERC-6538 `registerKeys` call whose
calldata is the meta-address, measured by `harness/registration` as real first-time
transactions with one fresh registrant per row:

| schemeId | meta-address, registered once | vs schemeId 1's 66 B | registration gas |
|---|---|---|---|
| 1 (classical) | 66 B | 1.0× | 115 310 |
| **3** | **1 250 B** | **18.9×** | **964 809** |

The measured object is the registry's **deployed runtime bytecode**, read off mainnet at
`0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538` and SHA-256-pinned beside the harness, because a
recompilation would price this machine's compiler settings instead. The payload is all-nonzero
by convention, so each figure is an upper bound rather than an exact cost, and the gap is
arithmetic: real key material carries about one zero byte in 256 and a zero calldata byte
costs 12 gas less on the standard EIP-7623 path these rows take — some 59 gas at 1 250 B,
derived per row by `tools/derive_sizes.py`.

**Registration is once per recipient per `schemeId`, not once per payment**, which is why this
table is separate from the one above. The 18.9x is a comparison against the classical scheme
and is meant as one; reading it as a per-payment figure is the single way to get it wrong.

**A whole payment IS measured, and the figure is 111 300 gas.** `harness/payment/` runs all
three transactions against a local node — announce, fund the derived address, then spend from
it with the derived key — and commits the receipts at `harness/payment/measured.json`:

| | announce | fund | spend | total |
|---|---|---|---|---|
| **schemeId 3** | 69 300 | **21 000** | **21 000** | **111 300** |

**The funding transfer is exactly the 21 000 intrinsic**, because a native-ETH transfer to an
EOA carries empty calldata and touches no contract. The same is true of the sweep. So for
native ETH there is nothing above intrinsic to measure on either side of the announcement,
and the announcement is the whole of this scheme's cost above a classical transfer. **For any
other asset it is not**: an ERC-20 transfer and an ERC-20 sweep both execute contract code,
neither is measured by this harness, and neither figure is quoted anywhere in this document.

### 7. Security considerations

**KEM anonymity is REQUIRED.** The public
ERC-6538 registry gives an adversary every candidate encapsulation key, so a ciphertext
linkable to its key deanonymises every payment without decryption.

**A delegated scanner learns the recipient's entire payment graph.** It cannot spend. It sees
every payment, their timing and their count. **That is the cost of delegating discovery — the
tracking key — and it is the only grain this scheme has.** A per-payment scheme offers no finer
one: the tracking key is all-or-nothing over the recipient's whole payment history.

**This scheme expires at a CRQC.** Spending is secp256k1, so once a CRQC exists the scheme is not a
usable scheme whatever its announcement layer does: the funds are already gone by the
paragraph above. It follows that **the EC half is not post-quantum protection of anything** —
by the time the quantum adversary arrives there is nothing left for it to protect.
Implementations and documentation MUST NOT present it as post-quantum protection.

What the hybrid is for is the interval **before** a CRQC exists. `ss` includes both `ss_ec`
and `ss_pq`, so evaluating the combiner needs both secrets. That is a statement about the
hash inputs, not a reduction in this document. It does **not** preserve announcement
anonymity if the ML-KEM ciphertext is linkable to the registered `ek`: `ct` and `ek` are
both public, and they are not rewritten by the hash. Implementations and documentation
MUST NOT claim that privacy survives either primitive failing.

**A leaked one-time key plus `ss` yields the master spending key, while a leaked one-time key
*alone* yields nothing.** Inherited from ERC-5564, not introduced here.

## Backwards Compatibility

**No consensus change, no new opcode, no change to ERC-5564 or ERC-6538.** This scheme uses
`announce()` and `registerKeys` unchanged, and adds nothing to either interface. The
`schemeId` field exists precisely to carry schemes these standards did not anticipate.

**One `schemeId` value awaits reservation** — 3. It is not reserved today.

**Existing schemeId 1 deployments are unaffected, and the skip rule is why.** A wallet that
supports only schemeId 1 encounters these announcements in the same event stream and skips
them on `schemeId`, which is mandatory behaviour rather than a courtesy. Nothing in this
document changes the meaning of an existing announcement, an existing meta-address, or an
existing registration, and the registry is keyed by `schemeId`, so registration under 1 and
under 3 coexists with no migration.

## Test Cases

**Fixtures exist and ship** — `vectors/section-*.json`, with a sha256 each in
`vectors/manifest.json`, regenerable and checkable with
`python3 tools/gen_vectors.py --check`. `vectors/PLAN.md` carries the row list the
generator reads and, per row, the normative sentence it pins.

**Twenty-seven rows pin this scheme**, in two groups rather than one, which is worth stating
because a reader expecting a single `schemeId 3` file will not find one:

| group | rows | what it pins |
|---|---|---|
| `vectors/section-1.json` | 7 | §1 — the offset derivation, the counter-reduction retry, the big-endian reading, the view tag |
| `vectors/section-2_9.json` | 20 | §2 — the 128-byte keygen seed and its scalar and determinism rules, the delegation window scan, the 1 250-byte meta-address and its point validation, the combiner and its bindings, the wire mapping, the address derivation, and what §2.7 calls a skip |

**What warrant each row carries is recorded in `vectors/rederivation.json`, not left to be
inferred.** Nineteen of the twenty-seven were re-derived by a second implementer from this
document's prose alone, with every expected value stripped, and that file's `bytes_disagree`
list being empty *is* the claim. The other eight were re-homed when the set was reduced with
this document — among them that a view-tag mismatch is a skip *and decapsulation does not
fail* — and are listed under `absent`: written after that re-derivation and witnessed by
nobody outside this project. `vectors/PLAN.md` maps each row to the sentence it pins.

## Reference implementation

**schemeId 3 is implemented alongside this document**, in `crates/per-payment` over
`crates/kem`, `crates/ec` and `crates/core`. Those four crates are the closure of this scheme's
dependencies: nothing else is needed to derive a key, build an announcement or scan for one.

The announcement-gas harness that produced §6's measured row is `harness/announcement/`,
`harness/registration/` measures the registration row, and `harness/payment/` measures all
three transactions of a payment against a local node.

**Unreviewed.** Nothing here has had external cryptographic review, and no conformance row
in this export has a witness outside this project — no third party has re-derived any of them.
A number of normative requirements are satisfied by the older external implementation only in
part: design decisions moved the specification ahead of that code. They are port obligations,
not defects.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE-CC0).
