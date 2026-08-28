# ERC-VVVV: Post-Quantum Stealth Addresses -- schemeId 3

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
| account | a plain EOA -- no batching account, no ERC-4337, no EIP-7702 |

This needs no protocol change, no new contract, and nothing of the sending account. 
The ECDH half is a migration hedge against a defect in an ML-KEM implementation, and it is
NOT post-quantum protection. Spending is secp256k1, so a quantum adversary ends this scheme
whatever its announcement layer does. 
schemeId 3 has a reference implementation against this document, in `crates/per-payment`.

## Motivation

### The announcement layer and the spending layer have different clocks

A stealth-address announcement is public and permanent. Anything an observer records today
can be broken later by a cryptographically relevant quantum computer, and the privacy loss is
**retroactive** -- harvest now, deanonymise later. 
That asymmetry says the announcement layer is the urgent one, and it can be upgraded without
touching the spending path. ERC-5564's `Announcement` and ERC-6538's `registerKeys` take
unbounded `bytes`, so nothing needs redeploying.

This ERC closes that retroactive hole. 

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described
in RFC 2119.

### 1. Common definitions

`ML-KEM-768` is as specified in FIPS 203, **unmodified in its algorithms and in its
parameters** -- and the **derandomised internal algorithms** are the ones this document
requires, not the public interface.

**Encapsulation MUST be deterministic in `m`**, and `m` MUST be the `encap_seed` of Section 2.4 --
a value the sender already holds -- rather than randomness the KEM samples for itself; without
that, `(ek, m)` does not fix `ct` and `ss_pq` and no conformance vector can pin an
announcement. And **the decapsulation key MUST be the 64-byte `(d, z)` seed** rather than the
expanded form. FIPS 203's `ML-KEM.Encaps` and `ML-KEM.KeyGen` draw their own randomness
and return an expanded `dk`, so an implementation MUST use **`ML-KEM.Encaps_internal(ek, m)`**
and **`ML-KEM.KeyGen_internal(d, z)`** -- Algorithms 17 and 16. **Decapsulation is NOT
constrained: `ML-KEM.Decaps` and `ML-KEM.Decaps_internal` are both permitted.**

A decapsulation key MUST be represented as the 64-byte `(d, z)` seed. This is the KEM half of
the **tracking key** delegated to a scanner.

The stealth derivation is ERC-5564's, unchanged:

```
stealth_pk = spending_pk + H(ss)*G
stealth_sk = spending_sk + H(ss)
H(ss)      = SHA256("pq-stealth/offset/v1" || ss), reduced to a valid scalar
view_tag   = SHA256("pq-stealth/view-tag/v1" || ss)[0]                     1 B
```

Scalar reduction MUST use one shared counter-based procedure for sender and recipient as described:

```
base = SHA256("pq-stealth/offset/v1" || ss)
for counter in 0, 1, 2, ... 256:
    candidate = base                                       if counter == 0
              = SHA256("pq-stealth/offset/v1" || base || u8(counter))   otherwise
    if 0 < candidate < n_secp256k1:  H(ss) = candidate; stop
fail
```

Convention: **every 32-byte digest above MUST be interpreted as a 256-bit unsigned integer in
big-endian order (uNbe)**, most significant byte first -- both for the comparison
`0 < candidate < n_secp256k1` and for the scalar that results. `u8(counter)` is a single byte,
and an implementation MUST fail rather than continue past `counter = 256`. Both sides run this
identical procedure.

#### 1.1 The hybrid combiner

schemeId 3 derives its **per-payment secret** by combining an ECDH shared secret with the
ML-KEM shared secret (Section 2.4). The construction is given here once.

```
hybrid_combine(DS, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
    = SHA3-256(DS || ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek)               32 B
```

The caller supplies the domain separator `DS` and names the output; Section 2.4 gives this scheme's
value, `"pq-stealth/hybrid-payment/v1"`, and names the output `ss`.
1. **`ss_ec` MUST be the x-coordinate alone**, 32 bytes, big-endian.
2. **The output MUST be the full 32-byte digest**, truncated nowhere, and the input order
   MUST be exactly `DS || ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek`.
3. **Explicitly**: `epk` and
   `viewing_pk_ec` are **33-byte SEC1-compressed** points; `ct` is the 1 088 announcement bytes; `ek` is the 1 184
   meta-address bytes; and `ss_ec` is the 32-byte x-coordinate per item 1.

**The IKM is in NIST SP 800-227.**
`H(K1, K2, c1, c2, ek1, ek2, domain_sep)`, and the **inputs** map onto it one for one:

| NIST input | here | why |
|---|---|---|
| `K1`, `K2` | `ss_ec`, `ss_pq` | the two shared secrets |
| `c1` | `epk` | the ephemeral public key **is** the DH ciphertext |
| `c2` | `ct` | the input SP 800-227's argument turns on |
| `ek1` | `viewing_pk_ec` | binds the secret to the recipient's identity |
| `ek2` | `ek` | redundant and added for conformance |
| `domain_sep` | the domain separator, the **first** hash input | already distinct per scheme |

**SHA3-256 rather than keccak256**, matching X-Wing and FIPS 202 (not onchain computation hence keccak256 is not necessary).
**Every added byte is already on the wire or in the registry, so the announcement does not grow and gas is unchanged.**

### 2. schemeId 3 -- per payment, hybrid

One encapsulation and one ephemeral key per payment. The announcement is an ephemeral public
key plus a one-byte view tag and a KEM ciphertext; spending stays secp256k1 ECDSA on an
ordinary EOA, so it needs no new verifier and no consensus change. Each announcement carries
a fresh encapsulation and a fresh ephemeral key, so two payments do not share those values.

```
sender    : esk, epk    <- a fresh ephemeral secp256k1 keypair
            (ct, ss_pq) <- ML-KEM-768.Encaps(ek, encap_seed)
            ss          <- hybrid_combine(..., ECDH(esk, viewing_pk_ec).x, ss_pq, ...)
            publish (epk, view_tag(ss) || ct); pay address(stealth_pk)
scanner   : ss_ec <- ECDH(viewing_ec, epk); ss_pq <- Decaps(dk, ct)
            ss <- the identical hybrid_combine call; check view_tag; recompute stealth_pk
recipient : stealth_sk = spending_sk + H(ss) mod n
```

#### 2.1 Keys and seeds

The keygen seed is `spending_seed(32) || viewing_ec_seed(32) || kem_seed(64)` = **128 bytes**.
An implementation MUST reject any other length rather than padding or truncating.

- `spending_seed` MUST be a valid secp256k1 scalar: `0 < spending_seed < n`, read big-endian
  per Section 1. It is the master spending key.
- `viewing_ec_seed` MUST be a valid secp256k1 scalar per Section 1. It is the viewing scalar
  `viewing_ec`, and it is **delegated**.
- `kem_seed` is ML-KEM's `(d, z)` pair as defined in Section 1, and becomes the decapsulation key
  verbatim. It is **delegated**.

**An implementation MUST reject a keygen whose spending scalar appears anywhere inside the
material that gets delegated -- and the delegated material is the 96-byte concatenation
`viewing_ec || dk` taken as a whole, not its two halves separately.** The test is a 32-byte
window scan at every one of the 65 offsets: **an implementation MUST scan the 96-byte
concatenation `viewing_ec || dk` at all 65 offsets, and MUST reject a keygen where any 32-byte
window of it equals `spending_seed`.**

```
if any 32-byte window of (viewing_ec || dk) equals spending_seed:  reject
```

Three outputs, with three different dispositions:

| output | contents | size | disposition |
|---|---|---|---|
| meta-address | `spending_pk(33) || viewing_pk_ec(33) || ek(1184)` | 1 250 B | **published** via ERC-6538 |
| master | `spending_sk` | 32 B | never leaves the owner |
| tracking | `viewing_ec || dk` | **96 B**, two secrets | **MAY be delegated** to a scanner |

Keygen MUST be deterministic in the seed: the same 128 bytes MUST produce the same three
outputs. Without that, conformance vectors are impossible.

#### 2.2 Meta-address encoding

```
meta = spending_pk(33) || viewing_pk_ec(33) || ek(1184)              1 250 B
```

- `spending_pk` and `viewing_pk_ec` MUST each be the SEC1 **compressed** encoding, 33 bytes.
- `ek` MUST be the 1 184-byte ML-KEM-768 encapsulation key of Section 1.

Decoding MUST reject a length other than 1 250, and MUST validate **both** points as curve
points **before** the meta-address is used for anything. `ek` is validated by the KEM on
first use; an implementation MUST NOT assume a well-formed length implies a well-formed key.

#### 2.3 Registration

A recipient MUST register the encoded meta-address via ERC-6538 `registerKeys` with
`schemeId` 3. **A recipient MAY register several `schemeId`s, per Section 6**, and a scanner MUST
use the set the recipient registered and MUST NOT process an announcement carrying any
`schemeId` outside it.

#### 2.4 Sender

The announce seed is **64 bytes**, `ephemeral_seed(32) || encap_seed(32)`. **A fresh seed MUST
be drawn for every announcement, and a seed MUST NOT be reused** -- across recipients, across
`schemeId`s, or across two payments to the same recipient. Per-`schemeId` uniqueness is not
enough: what MUST be unique is per announcement. Reuse repeats `epk`, which links the two
announcements to one sender, and against the same recipient it repeats `ss` and therefore the
stealth address, which merges two payments onto one key.

**How the seed is produced is deliberately outside this document.** A wallet deriving it from
a master key and an index satisfies the requirement, and so does a wallet drawing 64 fresh
random bytes; this document constrains the property, not the method.

```
esk         = ephemeral_seed                    a valid secp256k1 scalar per Section 1
epk         = SEC1-compressed(esk*G)                                       33 B
ss_ec       = x-coordinate of ECDH(esk, viewing_pk_ec)                     32 B
(ct, ss_pq) = ML-KEM-768.Encaps(ek, encap_seed)                 1 088 B / 32 B
ss          = hybrid_combine("pq-stealth/hybrid-payment/v1",
                              ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)    32 B
offset      = H(ss)                              per Section 1, big-endian, counter-reduced
stealth_pk  = spending_pk + offset*G
address     = keccak256(uncompressed(stealth_pk) without its 0x04 prefix)[12..32]
```

> **The domain separator above is implemented and pinned.** `crates/per-payment` uses it and
> `vectors/section-2_9.json` fixes its bytes, so it is a specified constant rather than a
> proposal.

Encapsulation MUST be deterministic in `encap_seed`, so that a vector fixing `(ek, m)` fixes
`ct` and `ss_pq`. The sender then:

1. publishes the announcement of Section 5 -- `epk` in `ephemeralPubKey`, the 1 089 bytes
   `view_tag(ss) || ct` in `metadata`; and
2. pays `address`.

**The `stealthAddress` field of the announcement MUST be the address derived above, and a
scanner MUST compare the address it derives against it.**

The sender learns `stealth_pk` but never `stealth_sk`, and MUST NOT be able to: the
recipient's `spending_sk` is the other addend.

#### 2.5 Scanner

Given the tracking key, the meta-address, and an announcement already classified as schemeId
3 per Section 6:

```
ss_ec <- x-coordinate of ECDH(viewing_ec, epk)
ss_pq <- Decaps(dk, ct)
ss    <- the identical hybrid_combine call of Section 2.4
if view_tag(ss) != announcement.metadata[0]:  not ours, skip
stealth_pk <- spending_pk + H(ss)*G
if address(stealth_pk) != announcement.stealthAddress:  not ours, skip
```

As the view tag is a
function of `ss`, it cannot be computed before decapsulation and the ECDH. This scheme
therefore has **no prefilter ahead of the KEM**: one ECDH and one ML-KEM-768 decapsulation are
paid on **every** announcement.

#### 2.6 Recipient

```
stealth_sk = (spending_sk + H(ss)) mod n
```

**A one-time key and its `ss` together recover the master spending key**, since
`spending_sk = stealth_sk - H(ss) mod n`. Implementations MUST NOT disclose both for the same
payment, and MUST NOT treat a one-time key as low-value on the grounds that it controls one
address. In particular a scanning service already holds every `ss`, so handing it any
one-time key hands it the master. Section 7 carries the general treatment.

#### 2.7 What is an error and what is a skip

| condition | scanner behaviour |
|---|---|
| `schemeId` != registered | skip |
| field lengths match no Section 6 row | skip |
| `epk` malformed or not a curve point | skip |
| `ct` malformed, `ek` malformed | skip |
| view-tag mismatch | skip |
| announced `stealthAddress` != the derived address | skip |
| decapsulation "fails" | **cannot happen** -- ML-KEM rejects implicitly |
| keygen seed not 128 bytes | error, at keygen |
| `spending_seed` or `viewing_ec_seed` not a valid scalar | error, at keygen |
| spending scalar found in delegated material | error, at keygen |
| meta-address length != 1 250, or either point not a point | error, at decode |

### 5. Wire formats and registry

Announcements MUST use ERC-5564's `announce()` unchanged. Meta-addresses MUST be registered
via ERC-6538 `registerKeys` with the matching `schemeId`.

1. **The view tag MUST be the first byte of `metadata`**, at `metadata[0]`, with no
   exception.
2. **`metadata` MUST be exactly `view_tag || ct`, in that order**, and an implementation MUST
   NOT reorder the fields.
3. **`ephemeralPubKey` MUST carry exactly `epk`**, and an implementation MUST NOT swap the
   two ERC-5564 fields.
   
### 6. Cost

Announcement cost, measured as **real standalone transactions** against the real ERC-5564
interface on anvil (`--hardfork prague`), with `gasUsed` read off the receipt. These are
**total transaction gas** -- the 21 000 intrinsic and every calldata byte included -- so no
convention needs stating. The generator ships beside the figures, at
`harness/announcement/measure.py`, and reads its field lengths from `tools/derive_sizes.py`
rather than retyping them; the receipts are committed at
`harness/announcement/measured.json`, and `tools/check_measured.py` re-derives every one of
them from the EIP-7623 rule with no node.

| schemeId | payload | calldata | execution | gas | floor binds | vs classical |
|---|---|---|---|---|---|---|
| 1 (classical, ERC-5564's own) | 34 B | 292 B | 5 143 | **28 067** | no | 1.00x |
| **3** | **1 122 B** | **1 380 B** | **14 269** | **69 360** | YES | **2.47x** |

> Both rows are measured

**The EIP-7623 calldata floor binds**, so execution gas is not charged at all -- the cost is
data availability.

**Registration is priced against the canonical registry itself.** Every row above is an
`announce()` call; a recipient also makes a one-time ERC-6538 `registerKeys` call whose
calldata is the meta-address, measured by `harness/registration` as real first-time
transactions with one fresh registrant per row:

| schemeId | meta-address, registered once | vs schemeId 1's 66 B | registration gas |
|---|---|---|---|
| 1 (classical) | 66 B | 1.0x | 115 310 |
| **3** | **1 250 B** | **18.9x** | **964 809** |

The measured object is the registry's **deployed runtime bytecode**, read off mainnet at
`0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538` and SHA-256-pinned beside the harness for precision.

**A whole payment IS measured, and the figure is 111 300 gas.** `harness/payment/` runs all
three transactions against a local node -- announce, fund the derived address, then spend from
it with the derived key -- and commits the receipts at `harness/payment/measured.json`:

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
every payment, their timing and their count. **That is the cost of delegating discovery -- the
tracking key -- and it is the only grain this scheme has.** A per-payment scheme offers no finer
one: the tracking key is all-or-nothing over the recipient's whole payment history.

**This scheme expires at a CRQC.** Spending is secp256k1, so once a CRQC exists the scheme is not a
usable scheme whatever its announcement layer does: the funds are already gone by the
paragraph above. It follows that **the EC half is not post-quantum protection of anything** --
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

**One `schemeId` value awaits reservation** -- 3. It is not reserved today.

**Existing schemeId 1 deployments are unaffected, and the skip rule is why.** A wallet that
supports only schemeId 1 encounters these announcements in the same event stream and skips
them on `schemeId`, which is mandatory behaviour rather than a courtesy. Nothing in this
document changes the meaning of an existing announcement, an existing meta-address, or an
existing registration, and the registry is keyed by `schemeId`, so registration under 1 and
under 3 coexists with no migration.

## Test Cases

**Fixtures exist and ship** -- `vectors/section-*.json`, with a sha256 each in
`vectors/manifest.json`, regenerable and checkable with
`python3 tools/gen_vectors.py --check`. `vectors/PLAN.md` carries the row list the
generator reads and, per row, the normative sentence it pins.

**Twenty-six rows pin this scheme**, in two groups rather than one, which is worth stating
because a reader expecting a single `schemeId 3` file will not find one:

| group | rows | what it pins |
|---|---|---|
| `vectors/section-1.json` | 7 | Section 1 -- the derivations every schemeId shares |
| `vectors/section-2_9.json` | 19 | Section 2 -- keys and seeds, the meta-address, the combiner and its bindings, the wire mapping, and what counts as a skip |

**What warrant each row carries is recorded in `vectors/rederivation.json`, not left to be
inferred.** Nineteen of the twenty-six were re-derived by a second implementer from this
document's prose alone, with every expected value stripped, and that file's `bytes_disagree`
list being empty *is* the claim. The other seven carry no outside witness at all, and
`python3 tools/gen_vectors.py` names them on every run rather than leaving the count to be
subtracted. `vectors/PLAN.md` maps each row to the sentence it pins.

## Reference implementation

**schemeId 3 is implemented alongside this document**, in `crates/per-payment` over
`crates/kem`, `crates/ec` and `crates/core`. Those four crates are the closure of this scheme's
dependencies: nothing else is needed to derive a key, build an announcement or scan for one.

The announcement-gas harness that produced Section 6's measured row is `harness/announcement/`,
`harness/registration/` measures the registration row, and `harness/payment/` measures all
three transactions of a payment against a local node.

**Unreviewed.** Nothing here has had external cryptographic review, and no conformance row
in this export has a witness outside this project -- no third party has re-derived any of them.
A number of normative requirements are satisfied by the older external implementation only in
part: design decisions moved the specification ahead of that code. They are port obligations,
not defects.

## Copyright

Copyright and related rights waived via [CC0](../LICENSE-CC0).
