---
eip: <not assigned>
title: Post-Quantum Stealth Addresses: schemeId 3 (hybrid, per payment)
description: One schemeId extending ERC-5564 with an ML-KEM-768 encapsulation combined with a secp256k1 ECDH secret, one announcement per payment, needing no protocol change and no per-counterparty state on either side.
author: <not assigned — see "Open before submission">
discussions-to: <none yet>
status: Draft
type: Standards Track
category: ERC
created: <not submitted>
requires: 5564, 6538
---

<!--
HAND-AUTHORED, and that is a difference from the other documents in this family worth
stating in the file itself. The two documents it is folded from -- a common-definitions
document and a per-payment document specifying this rung as a delta against an ML-KEM-only
one -- are generated from a common source, and their generator fails the build if a copy and
its source disagree on any per-section RFC 2119 keyword count. This document is not generated from either of them. It is
a FOLD: it takes the common material and the per-payment material, drops what belongs to
other rungs, and merges schemeId 3's four deltas into the sections they modify, so that one
document specifies one scheme with nothing to cross-reference.

What that costs is stated here rather than discovered: this document and the per-payment
document both specify one wire format, so they can DIVERGE. A conservation
gate in the authoring repository classifies every RFC 2119 occurrence in both sources and
fails if one classified as binding this rung has no counterpart here, or if a requirement
here traces to none — so divergence is visible on every build. The gate does NOT prove the
fold is correct: a delta folded wrongly conserves every keyword and still specifies the wrong
construction. Only a reader catches that, and the first reading is owed.

Status of the document: STARTER DRAFT, not submitted, not normative, nothing agreed.
-->

# ERC-VVVV: Post-Quantum Stealth Addresses — schemeId 3

> **STARTER DRAFT — NOT SUBMITTED, NOT NORMATIVE.**
>
> This is a starting point for named human authors to take over. Normative levels are
> written as MUST/SHOULD/MAY so the *shape* is right, but **nothing here is agreed**.
> Editor unassigned; conformance target unassigned; **schemeId 3 is not reserved**.
>
> **Where the paths in this document resolve: HERE.** Every relative path cited below —
> `harness/…`, `crates/…`, `vectors/…`, `tools/…` — resolves inside this repository, and a
> release gate fails on any citation that does not. The rule that makes this load-bearing:
> no number without a committed generator, where "committed" means committed in THIS tree —
> a figure whose harness lives somewhere a reader cannot reference is unfalsifiable.
>
> Every number cited names the committed generator that produces it — the reference
> implementation, or one of the harnesses in `harness/`. **This document quotes no withdrawn
> figure**, because the withdrawn ones price a rung it does not specify.

## Abstract

[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) defines stealth addresses and a registry
of `schemeId`s, of which only `schemeId 1` (secp256k1) is specified. This ERC specifies one
further scheme, **schemeId 3**, which makes the **announcement layer** post-quantum while
keeping **one announcement per payment** and no per-**counterparty** state on either side.

| | schemeId 3 |
|---|---|
| announcement secret | ML-KEM-768 **combined with a secp256k1 ECDH secret** |
| announcement | 1 129 B, one encapsulation and one ephemeral key per payment |
| meta-address | 1 250 B, registered once via ERC-6538 |
| spending | secp256k1 ECDSA |
| account | a plain EOA — no batching account, no ERC-4337, no EIP-7702 |
| state per counterparty | **none**¹ |

¹ "None per counterparty" is not "stateless": a sender keeps the sender-wide seed state of
§5 — a master and the next unused index, persisted atomically with sending, because a
repeated index repeats an announce seed and therefore a stealth address. What this rung
avoids is PAIRWISE state — nothing per counterparty, on either side.

**This needs no protocol change, no new contract, and nothing of the sending account.** That
is the sentence a wallet team reads to size integration cost — sized honestly: §5's
sender-wide seed state remains.

**The ECDH half is a migration hedge against a defect in an ML-KEM implementation, and it is
NOT post-quantum protection.** Spending is secp256k1, so a quantum adversary ends this scheme
whatever its announcement layer does. §9 gives the argument, and implementations MUST NOT
present the EC half otherwise.

**schemeId 3 has a reference implementation against this document**, in `crates/per-payment`.
The older *upstream* implementation does not: its `metadata` field order and its hybrid
combiner's input both differ from what this document specifies, so every payment secret it
derives differs from the specified one.

## Motivation

### The announcement layer and the spending layer have different clocks

A stealth-address announcement is public and permanent. Anything an observer records today
can be broken later by a cryptographically relevant quantum computer, and the privacy loss is
**retroactive** — harvest now, deanonymise later. Spending is different: an attacker who
breaks secp256k1 is forced to act *live*, against a key in use now.

That asymmetry says the announcement layer is the urgent one, and it can be upgraded without
touching the spending path. ERC-5564's `Announcement` and ERC-6538's `registerKeys` take
unbounded `bytes`, so nothing needs redeploying.

**That modularity is designed, not incidental.** BaseSAP — Wahrstätter, Solomon, DiFrancesco,
Buterin and Svetinovic (arXiv 2306.14272), four of whose five authors are ERC-5564's
authors — presents the stealth-address base layer as deliberately scheme-agnostic, each
cryptographic scheme layered on top under its own `schemeId`, and names quantum-resistant and
lattice-based schemes among the extensions the layering is built to carry. The scheme
specified here is an instance of exactly that extension model; its `schemeId` value is not
yet reserved (Backwards Compatibility states the reservation status).

### What this does not fix, stated up front

**Post-quantum is not the dominant privacy risk for stealth addresses today.** Kovács and
Seres (arXiv 2308.01703, ACM Web Conference 2024 (Companion)) measure **48.5% of Umbra
stealth-address users on Ethereum deanonymised by operational mistakes** — same-entity
withdrawal, gas-price fingerprinting, timing correlation, funding linkability — and 65.7% on
Arbitrum. None of that involves breaking a primitive.

This ERC closes a retroactive hole. It does **not** make a stealth address private against a
present-day observer. §8 is therefore normative, not advisory.

## Relationship to the four-document set

This document is **self-contained**: everything schemeId 3 requires is stated here, and no
`§N` reference leaves it. It is folded from a four-document set that specifies five schemeIds
together, and the map below is what a reader of that set needs in order to check this one
against it.

| this document's section | folded from | disposition |
|---|---|---|
| §1 Common definitions | the common-definitions document §1 | reduced to this rung |
| §1.1 The hybrid combiner | the common-definitions document §1.1 | **whole** — schemeId 3 *is* a hybrid rung, so this is core rather than common |
| §2.1 – §2.8 | the per-payment document §2.1 – §2.8 | **folded**, with §2.9's four deltas merged into §2.1, §2.2, §2.4/§2.5 and §6 |
| — | the per-payment document §2.9 | **dissolved**: §2.9 specified schemeId 3 as a delta against schemeId 2, and a document specifying schemeId 3 alone has nothing to take a delta against |
| §3, §4 | — | **not specified here**; see below |
| §5 Sender entropy | the common-definitions document §5 | whole argument, tables reduced |
| §6 Wire formats and registry | the common-definitions document §6 | reduced, with the delta-4 field mapping merged in |
| §7 Cost | the common-definitions document §7 | reduced to this rung's measured rows |
| §8 Operational requirements | the common-definitions document §8 | **whole**, less one row that binds a rung not specified here |
| §9 Security considerations | the common-definitions document §9 and the per-payment document's Security Considerations | reduced |

**Section numbers are preserved rather than renumbered, deliberately.** Renumbering would
break every reference that addresses a section by number — measured at over two thousand
across this project's files, a quarter of those in records that are not rewritten to make a
move look tidy — and would break the conformance fixtures, whose file names and row ids are
keyed to these numbers. The cost is that **§3 and §4 do not appear in this document**, which
is stated in place rather than left as a gap for a reader to wonder about.

### §3 and §4 — other rungs, not specified here

Two further rungs exist in the same `schemeId` registry and are specified in their own
documents: **schemeIds 4 and 5**, a pairwise-channel pair whose first contact costs one
announcement and whose subsequent payments cost an eight-byte memo, and **schemeId 6**,
post-quantum spending over a lattice signature.

**Two facts about them are load-bearing here**, and neither requires reading those
documents:

1. **Recognition.** §6's skip rule is by `schemeId`, and a schemeId 3 announcement shares
   both field lengths with a schemeId 5 first contact. A scanner that recognised by length
   would confuse them. §6 states this.
2. **Domain separation.** §1.1's combiner is shared with schemeId 5, and the two use
   distinct domain separators. §1.1 carries the requirement and §2.4 carries this rung's
   value; neither is restated here.

Nothing else in this document depends on them.

## Specification

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described
in RFC 2119.

### 1. Common definitions

`ML-KEM-768` is as specified in FIPS 203, **unmodified in its algorithms and in its
parameters** — and the **derandomised internal algorithms** are the ones this document
requires, not the public interface. The distinction is stated because "unmodified" alone is
misleading in a way that would stop a third implementer.

Two requirements in this document are only satisfiable through the internal entry points:
encapsulation MUST be deterministic in `m` (§2.4), and §5 requires `m` to be **derived**
rather than sampled; and the decapsulation key MUST be the 64-byte `(d, z)` seed rather than
the expanded form. FIPS 203's `ML-KEM.Encaps` and `ML-KEM.KeyGen` draw their own randomness
and return an expanded `dk`, so an implementation MUST use **`ML-KEM.Encaps_internal(ek, m)`**
and **`ML-KEM.KeyGen_internal(d, z)`** — Algorithms 17 and 16. **Decapsulation is NOT
constrained: `ML-KEM.Decaps` and `ML-KEM.Decaps_internal` are both permitted.**

`Decaps_internal` is deliberately **not** mandated. Neither stated reason reaches
decapsulation — `Decaps` draws no randomness and returns no key, and takes the same expanded
`dk`. Both properties this paragraph justifies, reproducible vectors and a 64-byte KEM
tracking key, come entirely from the two algorithms above. Mandating the internal form only
**removed FIPS 203's input checks** on the receiving side for no behavioural difference, and
made a MUST that an implementer on a validated module could fail while computing exactly the
right answer.

**In its place, one requirement that does work, and it is free.** A recipient or a delegated
scanner MUST recompute `ek` from its `(d, z)` seed and compare it against the `ek` in the
registered meta-address, at least once before scanning — **and the same requirement covers
the viewing half: the point derived from the delegated viewing scalar MUST be compared
against the registered `viewing_pk_ec` in the same pass.** Without the `ek` half there is **no
mechanism anywhere in this document by which a corrupt tracking key surfaces** — a `d` half
corrupted by one bit expands through `KeyGen_internal` into a self-consistent keypair for a
*different* key, so FIPS 203's own `dk` check would pass, and the delegated scanner reports
zero payments for ever with no error. Without the viewing half the SAME silent zero exists
for the other delegated secret: a wrong viewing scalar does ECDH against a point no sender
uses, every genuine announcement returns "not ours", and nothing downstream can tell — an
implementation of the `ek` half alone passes every setup step and then finds nothing,
forever. §2.5 asserts that such an error MUST surface; the two comparisons together are what
make that assertion true rather than aspirational.

**This rung is the one where both halves are needed**, because its tracking key is two
secrets rather than one (§2.1). An implementation carrying the `ek` comparison over from a
non-hybrid rung and stopping there satisfies half the requirement and inherits the whole
failure.

**What the comparison does NOT detect, stated because half the KEM tracking key is outside
it.** `ek` is a function of `d` alone; `z` is FIPS 203's implicit-rejection secret and enters
`dk` only. So a corruption confined to `z` — 32 of the 64 KEM bytes — passes this check, and
it is harmless: decapsulating a genuine ciphertext runs the re-encryption check, that check
succeeds, and the true shared secret is returned whatever `z` holds. `z` is consulted only on
the rejection path, whose output is pseudorandom either way and which a scanner treats as
"not ours" either way. **The requirement is therefore aimed at exactly the half where
corruption is both undetectable and fatal**, and an implementation MUST NOT extend it to a
claim of integrity over the whole seed.

> **The boundary is testable, in both directions.** Flip a bit in `z` and the comparison
> stays clean; flip one in `d` and the comparison fails — a test asserting only the mismatch
> half holds half a reason. Both halves are asserted in the reference implementation, which
> is what a boundary in a requirement is worth. A delegated scanner reconstructs `ek` and
> `viewing_pk_ec` in any case, per §1.1 item 4, so the comparison costs two equality tests.

**This is a real constraint on implementers and is not a modification of the primitive.**
Nothing about the algorithms or parameters changes; what changes is which documented entry
point is called. But a FIPS-validated cryptographic module frequently exposes only the public
interface, so **an implementer relying on a validated module MAY find it has no API that
accepts `m` or `(d, z)`** and will need one that does. That cost is stated here rather than
discovered, and it is the price of the two properties it buys: reproducible conformance
vectors, and a 64-byte KEM tracking key instead of a 2 400-byte one. Implementations MUST NOT
substitute a round-3 Kyber variant.

A decapsulation key MUST be represented as the 64-byte `(d, z)` seed. This is the KEM half of
the **tracking key** delegated to a scanner, and the representation is what makes it 64 bytes
rather than 2 400.

The stealth derivation is ERC-5564's, unchanged:

```
stealth_pk = spending_pk + H(ss)·G
stealth_sk = spending_sk + H(ss)
H(ss)      = SHA256("pq-stealth/offset/v1" ‖ ss), reduced to a valid scalar
view_tag   = SHA256("pq-stealth/view-tag/v1" ‖ ss)[0..8]                     8 B
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

**Every 32-byte digest above MUST be interpreted as a 256-bit unsigned integer in big-endian
order**, most significant byte first — both for the comparison `0 < candidate < n_secp256k1`
and for the scalar that results. This is easy to leave unstated and it is not inferable. Both
reference implementations read big-endian, the Rust through `SecretKey::from_slice` and the
TypeScript through a left-shifting `bytesToBigInt`; an implementation reading little-endian
would derive a different scalar from the same shared secret, therefore a different one-time
address, therefore funds its recipient cannot spend. The failure is silent and total.

`u8(counter)` is a single byte, and an implementation MUST fail rather than continue past
`counter = 256`. The reason is exhaustion, not overflow: `counter = 0` contributes no counter
byte at all, and counters 1 … 256 contribute byte values `0x01 … 0xFF` and then `0x00`, so
the loop tries `base` plus all 256 distinct single-byte values — 257 distinct inputs, none
repeated. A `counter = 257` would re-derive the `0x01` candidate already rejected, so no
further iteration could ever succeed.

Both sides run this identical procedure.

**The view tag is eight bytes, and it is an exact matcher rather than a prefilter.** It sits
at the front of `metadata` per §6, and a scanner that has derived `ss` MUST compare all eight.

**Why the width is not a privacy dial here, where in ERC-5564 it is.** ML-KEM rejects
implicitly, per the paragraph above: decapsulating a ciphertext addressed to somebody else
returns a pseudorandom shared secret and no error. The KEM therefore gives a scanner **no**
signal about whether an announcement is its own, the view tag is the only signal there is,
and its width is how much of that signal a scanner gets. At one byte a scanner does not know,
and it MUST resolve the remaining ambiguity by querying chain state for the derived address —
which is the disclosing step §9's RPC paragraph is about. A narrow tag does not avoid that
leak; it **makes the leak necessary**.

A counter-argument worth naming so a reader does not reconstruct it: that a 1-in-256
false-positive rate is cover traffic, because a wallet filtering to exactly its own payments
makes its subsequent state queries a set equal to its payment set. This document rejects it,
with the reason in §2.8 and the resolution in §9. It needs an observer of the scanner's
queries to be covered *from*, and the norm is a recipient scanning against their own node,
where there is none; where a scanner is delegated, §9 records that it already holds the
entire payment graph — so the cover was protecting the smaller leak. **The one deployment
where the argument survives** — local event scanning with third-party state queries — is a
mitigation belonging in §8 beside §9's RPC paragraph, not a wire-format field width.

**What it costs is seven bytes per announcement**, priced in §7. What it buys is that a
scanner which has derived `ss` knows, at 2⁻⁶⁴. Whether there is any *value* at the derived
address is a separate question that no tag answers; §8 and §9 are where it lives.

> This construction is stated in FULL here, deliberately — a spec that says only "reduced to
> a valid scalar" leaves the counter-based procedure to live in a reference implementation,
> and two implementations agreeing on it then demonstrates that the second read the first,
> not that the text was precise enough to implement from. It is written out here so that a
> third implementation can be written from this document alone. The same applies to §5's
> integer widths.

#### 1.1 The hybrid combiner

schemeId 3 derives its **per-payment secret** by combining an ECDH shared secret with the
ML-KEM shared secret (§2.4). The construction is given here once.

```
hybrid_combine(DS, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
    = SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek)               32 B
```

The caller supplies the domain separator `DS` and names the output; §2.4 gives this rung's
value, `"pq-stealth/hybrid-payment/v1"`, and names the output `ss`.

**One other scheme in the same registry uses this construction, and the separators MUST be
pairwise distinct across schemes**, because a channel key and a payment secret MUST NOT be
derivable from one another. schemeId 5's separator is given in its own document; an
implementation that supports both MUST share this code rather than carry a copy per scheme.

**Four parameters of this construction are load-bearing and none is inferable — each is
stated because a one-line form would leave it to be guessed.** Both reference implementations
agree on the first, and each parameter produces a silently different output if chosen
otherwise:

1. **`ss_ec` MUST be the x-coordinate alone**, 32 bytes, big-endian — not the full point, not
   a compressed encoding, and not a hash of either.
2. **The domain separator is the FIRST input, then the six fields.** An implementation MUST
   NOT append it, and MUST NOT length-prefix it. *The derivation is a direct hash, so no salt
   question arises — one fewer interop-critical parameter of exactly the kind this list
   exists for.*
3. **The output MUST be the full 32-byte digest**, truncated nowhere, and the input order
   MUST be exactly `DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek`.
4. **Every IKM field is the bytes as they appear on the wire or in the registry, at the
   lengths §6 gives**, and no field is re-encoded. The encodings are pinned explicitly
   because the order alone does not fix them — without this rule the only thing fixing them
   would be an incidental sentence giving the total as 2 402 bytes. Explicitly: `epk` and
   `viewing_pk_ec` are **33-byte SEC1-compressed** points, not 65-byte uncompressed and not
   32-byte x-coordinates; `ct` is the 1 088 announcement bytes; `ek` is the 1 184
   meta-address bytes; and `ss_ec` is the 32-byte x-coordinate per item 1, which is the one
   field that is *not* a wire encoding. **This matters most for a delegated scanner**, which
   holds only the 96-byte tracking object and MUST reconstruct `viewing_pk_ec` and `ek` — the
   one place in the protocol where an implementer chooses an encoding rather than copying
   one, and therefore the place a divergence produces an address the recipient never derives,
   with no error on either side.

`epk` MUST be bound into the KDF. Without it, flipping the compressed parity byte yields the
same ECDH x-coordinate and therefore the same payment secret.

**The IKM is the combiner NIST SP 800-227 puts forward, with this document's field names —
all six fields, not the shorter `ss_ec ‖ ss_pq ‖ epk`.** The reason is not tidiness — the
shorter form is not known to deliver the property the hybrid exists to provide:

> SP 800-227 section 4.6.3 (final, September 2025) holds that a combiner over the two shared
> secrets alone, `KDF(K1, K2)`, **does not preserve IND-CCA security regardless of the
> properties of the KDF** — one component can be broken badly enough to destroy the composite
> even when the other is sound.

A broken ML-KEM implementation is exactly the failure this rung hedges, so a combiner without
that preservation property hedges less than it appears to. The combiner NIST puts forward
instead is `H(K1, K2, c1, c2, ek1, ek2, domain_sep)`, and the **inputs** map onto it one for
one:

| NIST input | here | why |
|---|---|---|
| `K1`, `K2` | `ss_ec`, `ss_pq` | the two shared secrets |
| `c1` | `epk` | the ephemeral public key **is** the DH ciphertext |
| `c2` | `ct` | the input SP 800-227's argument turns on |
| `ek1` | `viewing_pk_ec` | binds the secret to the recipient's identity |
| `ek2` | `ek` | see below |
| `domain_sep` | the domain separator, the **first** hash input | already distinct per scheme |

**Every added byte is already on the wire or in the registry, so the announcement does not
grow and gas is unchanged.** The IKM is 2 402 bytes where it was 97; that is hash input
against an ML-KEM decapsulation, which is not a cost worth optimising.

**The inputs and the combiner shape both map onto SP 800-227's; the PROPERTY does not.** The
combiner that section puts forward is a **direct hash** modelled as a random oracle, and the
decision below makes this document's combiner one too, so one gap remains rather than two:
theirs is IND-CCA preservation, ours is anonymity. The honest statement of the position is
*the inputs are the ones NIST recommends, the combiner shape is the one its result analyses,
and the property is different.*

**The combiner is a direct SHA3-256 hash, not HKDF-SHA256.** The deciding argument is not the
theorem fit but what HKDF is for: **`HKDF-Extract` exists to condition non-uniform entropy,
and there is none here to condition.** Both inputs are already uniform 32-byte shared
secrets, so extract-then-expand's structure is being paid for a property this construction
does not use — and paying for it is what put the derivation outside the function SP 800-227's
result analyses.

Four further reasons, in descending weight:

1. **It is the construction the cited result covers.** SP 800-227 §4.6.3's example combiner
   is a direct hash modelled as a random oracle; the IND-CCA-preserving property is proven
   for that shape. No gap left to explain to a reviewer.
2. **X-Wing does the same**, and it is the most-reviewed post-quantum hybrid combiner in this
   ecosystem, so an implementer has byte-testable reference code — `@noble/post-quantum`'s
   `ml_kem768_x25519` among others. This document declines X-Wing's *construction* while
   agreeing with its *combiner shape*, which is a coherent position and worth stating as one.
3. **One fewer interop-critical parameter.** The absent-salt requirement disappears entirely
   rather than needing to be specified, tested and got wrong — and an unstated salt is
   precisely the kind of parameter two implementations can agree on by accident, each
   defaulting the same way, with nothing in either test suite forcing the question.
4. **Simpler to state and to verify**: one hash call over a defined byte string.

*The apparent counterexample is TLS, whose hybrid concatenates into an HKDF key schedule. Its
binding comes from a transcript hash covering the ciphertexts and public keys — machinery
this construction does not have, which is why the inputs carry it here instead.*

**SHA3-256 rather than keccak256**, matching X-Wing and FIPS 202. Keccak would be EVM-native,
and that is the only argument for it; this scheme derives no payment secret on chain, so it
buys nothing today. A future revision that needs on-chain derivation MUST revisit this, and
the change would be breaking.

**The fixtures exist and ship, so a change of this kind is no longer free**: any
re-derivation of the combiner is now a breaking change against published vectors.

**`ek` is redundant and is included anyway.** FIPS 203 Algorithm 17 derives ML-KEM's own
shared secret as `(K, r) ← G(m ‖ H(ek))`, so the recipient's encapsulation key is *already*
bound inside `ss_pq` and binding it again adds nothing cryptographically. It is listed
because the alternative is a combiner that departs from the shape NIST puts forward and asks
every reader to verify a FIPS 203 internal before accepting the omission — and inputs omitted
to save something invisible have a way of becoming gaps that get argued about. **This is the
one part of the IKM worth revisiting if the 1 184 bytes ever matter**; nothing else in the
list is droppable.

**Two limits on the argument, stated so nobody over-reads it.** SP 800-227's property is
IND-CCA preservation and what this document needs is anonymity preservation, so the
structural lesson transfers but the theorem does not; the negative result NIST cites SHOULD
be read before this is treated as settled. And the anonymity chain in §9 is unaffected — its
undischarged premise sits underneath the hybrid and the non-hybrid rungs alike.

**Port-time obligation, and it is a breaking change.** Both reference implementations already
agree on the old three-field IKM, so every payment secret they derive changes. No deployment
exists, so the cost is confined to the port; after fixtures exist there is no cheap moment for
this. A conformance claim for either older implementation MUST record the affected
requirements as unsatisfied until the port lands.

### 2. schemeId 3 — per payment, hybrid

One encapsulation and one ephemeral key per payment. The announcement is an ephemeral public
key plus an eight-byte view tag and a KEM ciphertext; spending stays secp256k1 ECDSA on an
ordinary EOA, so it needs no new verifier and no consensus change. **Forward secrecy is per
payment**, because every announcement carries a fresh encapsulation *and* a fresh ephemeral
key. **There is no per-counterparty state** on either side — §5's sender-wide seed state
remains — which is what makes this rung a drop-in for ERC-5564 as deployed.

**What the ECDH half is for is stated once, in §9, and it is not post-quantum protection.**
Spending is secp256k1, so a CRQC ends this rung regardless. The EC half covers the interval
before that, against a failure of the ML-KEM implementation. Implementations MUST NOT present
it otherwise.

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

The reason is specific to this rung. The tracking key **is** those 96 bytes, so
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

- `spending_pk` and `viewing_pk_ec` MUST each be the SEC1 **compressed** encoding, 33 bytes,
  with a leading tag byte of **`0x02` or `0x03` only**. An implementation MUST reject any
  other encoding of the same point, and MUST use **one decoder** for both.
- `ek` MUST be the 1 184-byte ML-KEM-768 encapsulation key of §1.

**Why the tag restriction, since it is the rule most likely to be relaxed by an implementer
who sees no harm in it.** SEC1 also defines a **compact** representation with a `0x05` tag,
which the RustCrypto stack canonicalises to the same point as `0x02`. Accepting it would give
one key two distinct on-chain encodings, so one registered meta-address would have two byte
representations and any equality test over encoded bytes would be wrong for one of them.
Restricting the tag makes the second encoding unrepresentable rather than rejected downstream.

Decoding MUST reject a length other than 1 250, and MUST validate **both** points as curve
points **before** the meta-address is used for anything. `ek` is validated by the KEM on
first use; an implementation MUST NOT assume a well-formed length implies a well-formed key.

#### 2.3 Registration

A recipient MUST register the encoded meta-address via ERC-6538 `registerKeys` with
`schemeId` 3. **A recipient MAY register several `schemeId`s, per §6**, and a scanner MUST
use the set the recipient registered and MUST NOT process an announcement carrying any
`schemeId` outside it.

**That is a skip, not an error.** `announce()` is permissionless, so an error would be a
permanently abortable scan that any stranger could trigger for one announcement's gas — the
failure §2.5, §2.7 and §9 each forbid separately. And **no order over the registry's
schemeIds exists to be "downgraded" along**: the ML-KEM-only per-payment rung has per-payment
forward secrecy and no classical floor, the hybrid channel rung has the floor and no forward
secrecy, and schemeId 3 has both, so those two are incomparable. A recipient simply never
derives a key for a `schemeId` it did not register, which needs no ordering and no error
path. See §6.

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

**`hybrid_combine` is specified in §1.1 and is not restated here.** Its four load-bearing
parameters, the field encodings, the `epk`-binding requirement, the SP 800-227 mapping and
the direct-hash decision are all given there once. What this section supplies is the two
things that are its own: the domain separator `"pq-stealth/hybrid-payment/v1"`, and that the
output is named `ss` and is consumed as this section's payment secret. **This separator MUST
differ from the one the hybrid channel rung supplies** — §1.1 states the requirement from the
other side, and it is the same requirement.

> **The domain separator above is implemented and pinned.** `crates/per-payment` uses it and
> `vectors/section-2_9.json` fixes its bytes, so it is a specified constant rather than a
> proposal.
>
> It is worth stating separately because an equivalent parameter CAN sit unstated while two
> implementations agree on it by accident — the order that produces a constant nobody chose.
> This one is written down first and implemented second.

Encapsulation MUST be deterministic in `encap_seed`, so that a vector fixing `(ek, m)` fixes
`ct` and `ss_pq`. The sender then:

1. publishes the announcement of §6 — `epk` in `ephemeralPubKey`, the 1 096 bytes
   `view_tag(ss) ‖ ct` in `metadata`; and
2. pays `address`.

**The `stealthAddress` field of the announcement MUST be the address derived above.** A
sender that announces one address and pays another has made a payment its recipient cannot
find. Note that this places a value on chain which a recipient could re-derive and compare;
whether a scanner MUST do so is **not** settled by this specification — see §2.8.

The sender learns `stealth_pk` but never `stealth_sk`, and MUST NOT be able to: the
recipient's `spending_sk` is the other addend.

#### 2.5 Scanner

Given the tracking key, the meta-address, and an announcement already classified as schemeId
3 per §6:

```
ss_ec ← x-coordinate of ECDH(viewing_ec, epk)
ss_pq ← Decaps(dk, ct)
ss    ← the identical hybrid_combine call of §2.4
if view_tag(ss) ≠ announcement.metadata[0..8]:  not ours, skip
stealth_pk ← spending_pk + H(ss)·G
```

**`metadata[0..8]` is the view tag**, and that is an invariant the wire formats were chosen to
preserve rather than an accident of this section: it holds here because §6 puts the tag ahead
of `ct`, and it holds in every other scheme in the registry that carries a tag. A section
that imports this block by reference therefore inherits a correct offset, which is the
property the layout buys.

**The order is forced and is a cost floor, not an implementation choice.** The view tag is a
function of `ss`, so it cannot be computed before decapsulation and the ECDH. This rung
therefore has **no prefilter ahead of the KEM**: per-announcement scanning cost is one
ML-KEM-768 decapsulation **plus one scalar multiplication**, on input that anyone can publish.
An implementation SHOULD account for that when sizing a scanning service, and §8's
requirement to defer or batch balance lookups applies.

**ML-KEM rejects implicitly**, by design and per §1: decapsulating a ciphertext addressed to
somebody else returns a pseudorandom `ss_pq` rather than an error, and the combiner turns
that into a pseudorandom `ss`. A scanner therefore MUST NOT treat a decapsulation result as
evidence of anything by itself. The view tag is the only filter this rung has. At eight bytes
(§1) it admits a foreign announcement with probability **2⁻⁶⁴**, so in practice a scanner
that reaches the curve arithmetic is handling its own payment; the decapsulation and the
scalar multiplication, not the filter, are the cost.

**A derived stealth address identifies ONE payment. A scanner MUST NOT present two
announcements that derive the same address as two payments.**

**The reachable case is a replay, and it needs no cryptography to arrange.** `announce()` is
permissionless, so anyone can republish an announcement verbatim: the same `epk`, the same
`ct`, the same eight-byte tag, the same `ss`, the same derived address. Both copies pass
every check in this section, and a scanner that reports each one shows its user **one payment
twice, at one address, with no error** — a false balance and a history that does not
reconcile against chain state. No funds are lost and none can be: it is the same address.

**The comparison MUST be on the twenty derived address bytes.** Two independent derived keys
collide at about 2⁻¹⁶⁰, and dropping a real payment on such a collision is the cost of this
rule; deduplicating on the offset instead would move that to 2⁻²⁵⁶ at the price of keeping a
secret-derived value in the scanner's index. **This document accepts the 2⁻¹⁶⁰**, and says so
rather than leaving the choice of key to an implementer, because the two behave differently
and neither is visible from the outside.

**Every negative outcome MUST be "not mine", and MUST NOT abort the scan.** That includes a
`schemeId` mismatch, field lengths matching no row of §6, a malformed `epk`, `ek` or `ct`,
and a view-tag mismatch.

These MUSTs bind the **scanner entry point** — the function a caller hands chain-derived
announcements to. A lower-level routine MAY signal a malformed input as an error, provided
the entry point converts it to "not mine" before any caller sees it; both reference
implementations are layered that way, and it is deliberate, since an error from further in
can also mean a corrupt *tracking key*, which is the owner's problem and MUST surface. An
implementation that exposes the inner routine as its scanning API inherits the wrong
behaviour. `announce()` is permissionless and every announcement is permanent, so a scanner
that raises on one hostile input loses **every** payment rather than one, and does so again
on every future rescan. Both reference implementations did exactly this at some point.

#### 2.6 Recipient

```
stealth_sk = (spending_sk + H(ss)) mod n
```

A wallet SHOULD verify that the derived key controls the derived address — as a
key-to-address relation, not merely that bytes were produced — before presenting the payment
as spendable.

**That check is arithmetic, and it establishes only one of three separate things.** It takes
no chain input and cannot, so it MUST NOT be read as evidence that a payment exists:

| | question | answer comes from | specified here |
|---|---|---|---|
| 1 | does the derived key control the derived address? | the derivation alone | yes, above |
| 2 | did someone announce to me? | a chain **event** | yes, §2.5 — and `announce()` is permissionless |
| 3 | did value arrive at that address? | chain **state** | **yes, as a SHOULD — below** |

**A wallet SHOULD confirm that value arrived before presenting a payment as received or
spendable.** It is a SHOULD and not a MUST because satisfying it needs chain access beyond
the announcement log, and every other requirement in this document is discharged from the
announcement, the meta-address and local key material alone. A wallet that cannot reach chain
state MUST present the payment as *announced* rather than as *received*.

**The two asset types do not share a mechanism, and an implementer MUST know which one they
are in.** An ERC-20 credit emits a `Transfer` event with an indexed `to`, so a scanner
already reading logs confirms it with a filter on an address it has just derived. **A plain
ETH transfer to an EOA emits no log at all**, so confirming it means chain state — a balance
query per candidate address — which costs a round trip and sharpens the retrieval leak of §8
in exactly the way the next subsection describes. An implementation SHOULD therefore batch or
defer ETH balance queries, per §8, and MUST NOT issue one per announcement as it scans.

(2) does not imply (3). `view_tag` is a function of `ss`, and the *sender* holds `ss` from
its own derivation against a public `viewing_pk_ec` and `ek`, so nothing prevents anyone from
publishing a well-formed announcement that a scanner accepts as its own with no payment
behind it. The cost is one announcement; no cryptographic break is involved. §2.7 gives the
disposition.

**A one-time key and its `ss` together recover the master spending key**, since
`spending_sk = stealth_sk − H(ss) mod n`. Implementations MUST NOT disclose both for the same
payment, and MUST NOT treat a one-time key as low-value on the grounds that it controls one
address. In particular a scanning service already holds every `ss`, so handing it any
one-time key hands it the master. §9 carries the general treatment.

#### 2.7 What is an error and what is a skip

| condition | scanner behaviour |
|---|---|
| `schemeId` ≠ registered | skip |
| field lengths match no §6 row | skip |
| `epk` malformed or not a curve point | skip |
| `ct` malformed, `ek` malformed | skip |
| view-tag mismatch | skip |
| an announcement deriving an address already presented | **skip, and present no payment.** Reached on the SUCCESS path, not a failure path: a replay's tag verifies because the bytes are identical. §2.5 carries the rule and the 2⁻¹⁶⁰ collision cost it accepts |
| announcement matches, no value at the derived address | **not an error and not a skip** — the announcement was addressed to this recipient, and a wallet SHOULD confirm value before presenting it as received (§2.6). Neither outcome is a scanning failure |
| decapsulation "fails" | **cannot happen** — ML-KEM rejects implicitly |
| keygen seed not 128 bytes | error, at keygen |
| `spending_seed` or `viewing_ec_seed` not a valid scalar | error, at keygen |
| spending scalar found in delegated material | error, at keygen |
| meta-address length ≠ 1 250, or either point not a point | error, at decode |

The distinction is not stylistic: everything a *third party* can cause is a skip, and
everything the *owner* can cause is an error. An implementation that inverts this converts a
permissionless write into denial of service.

#### 2.8 What this section does not specify

Named rather than left to be discovered:

- **Whether a payment exists at all** — answered in §2.6, as a SHOULD on presentation with
  the ETH/ERC-20 asymmetry stated there. What remains unspecified is narrower and worth
  keeping in this list: **how many confirmations, if any**, a wallet waits for before
  presenting a confirmed payment as spendable. That is a reorg-safety question this document
  takes no position on. Neither reference implementation performs the existence check in its
  scanning library — it appears only in demo and test code, against an in-memory mock chain —
  so the SHOULD is satisfied by neither and is a port-time obligation.
- **A scanner MAY compare the announced `stealthAddress` against the address it derives.
  This document does NOT oblige it to, and an implementation that omits the comparison is
  conforming.** The comparison authenticates a match at 160 bits for the cost of a
  comparison. In the reference implementation in `crates/per-payment` a parsed announcement
  keeps the **announced** address and a match reports the **derived** one, so a caller holds
  both and the comparison is one equality away; the library does not perform it for them,
  because this document leaves it optional. The parser did once discard the announced field,
  filling it with twenty zero bytes, which made the comparison a guaranteed false negative
  against anything a scanner read off a log. That is worth naming because it is the shape a
  reimplementation falls into rather than an accident: the address is `announce()`'s second
  argument and a scanner reading the event already has it, so a parser taking only the two
  payload fields has dropped it rather than never having had it.

  **The trade that justified the MAY is WITHDRAWN, and it is withdrawn because the view tag
  is eight bytes.** The argument was that the comparison filters the phantom announcement of
  §2.6 but also removes the cover traffic a 1-in-256 false-positive rate provides: filter the
  false positives out and a scanner's balance queries become exactly its payment set, which
  is more informative to whoever answers them. That was a real trade at one byte. At eight
  the scanner's query set is already its payment set **before** the comparison, at 2⁻⁶⁴, so
  there is no cover left for the comparison to remove and the trade has no second side.

  **§1 gives the reason the width changed and §9 gives the resolution.** The short form is
  that cover traffic needs an observer of the queries to be covered *from*; the norm is a
  recipient scanning against their own node, and a delegated scanner already holds the whole
  payment graph. The one deployment where the argument survived — local event scanning with
  third-party state queries — is a mitigation in §8 and not a field width.

  **What this leaves is an under-justified normative level, and it is recorded rather than
  quietly changed.** The comparison is now free: it filters §2.6's phantom announcement and
  discloses nothing the eight-byte tag has not already disclosed. Its only stated reason for
  being a MAY was the trade above, so **whether the level ought now to be SHOULD is an open
  question for the author** and is listed in `Open before submission`. It stays a MAY here
  because raising a level is a normative change and is not made in passing here.

- **Constant-time or side-channel requirements.** None are stated anywhere in this document,
  and the tracking key is designed to be delegated to a service whose timing a third party
  can observe.
- **The KEM anonymity argument** on which unlinkability rests. §9 gives it, and states that
  it is derived here rather than cited, in the ROM, with one premise undischarged.
- **Conformance vectors.** Required by §6's recognition rules and by §1's reduction
  procedure; published — `vectors/section-*.json`, with a sha256 each in the manifest,
  independently re-derived from this document's prose.

**One relationship to the ML-KEM-only per-payment rung is a requirement rather than a
remark.** From `ss` onward — `H(ss)` per §1, the view tag, the address, the scanner order,
the error/skip table — schemeId 3 and the ML-KEM-only rung are byte-identical, and an
implementation that supports both MUST share that code rather than duplicate it. This is
stated here because it is checkable: one public function, and a reader can confirm there is
one.

### 5. Sender entropy — normative

Announcement seeds MUST NOT be reused. Implementations SHOULD derive them:

```
seed_i = SHAKE256("pq-stealth/sender-seed/v1" ‖ master(32) ‖ u64be(i)
                   ‖ u64be(schemeId) ‖ u64be(|rung|) ‖ rung
                   ‖ u64be(|kem_id|) ‖ kem_id, n)

kem_id = u64be(|kem_name|) ‖ kem_name          -- a bare KEM
       = u64be(|wrapper|) ‖ wrapper ‖ u64be(|kem_id_inner|) ‖ kem_id_inner
                                                -- a KEM wrapping another
```

with `i` strictly increasing and persisted monotonically. All integers are **eight bytes,
big-endian**; `n` is the announce-seed length of the scheme the seed is drawn for — **64 for
schemeId 3**; `rung` is the scheme's canonical name, length-prefixed so that no two names can
concatenate into one another.

**A seed that does not yield a valid scalar MUST be rejected and the index advanced.**
`ephemeral_seed` is read as a secp256k1 scalar per §1, and a 32-byte string is a valid scalar
only with overwhelming probability, not certainly. The procedure is rejection sampling on
`i`, in the shape FIPS 204 uses for its own signing loop:

```
i ← the sender's next unused index
loop:
    seed_i ← SHAKE256(… ‖ u64be(i) ‖ …, 64)
    split seed_i as ephemeral_seed(32) ‖ encap_seed(32)
    if ephemeral_seed is a valid scalar (0 < s < n_secp256k1, big-endian):  use it; stop
    i ← i + 1                          -- the rejected index MUST NOT be reused
```

**The rejected index MUST NOT be retried and MUST NOT be reused for a later announcement.**
Advancing `i` is what keeps the seed stream injective; reusing a rejected index would mean
two announcements could later draw the same seed, which is the failure the whole of this
section exists to prevent. A recipient never walks this loop — it recovers from published
material, not from the sender's index — so unlike §1's scalar retry this procedure is not one
both parties MUST reproduce identically. It is normative anyway, because a sender that fails
hard here produces a wallet that stops working with probability about 2⁻¹²⁸ per payment
instead of advancing an integer.

**This rung draws an `ephemeral_seed` and therefore walks this loop.** A rung whose announce
seed is `encap_seed` alone does not, because ML-KEM accepts any 32-byte string.

**`master` is the sender's own 32-byte announcement master, and it is not any key.** Left
undefined it would have two readings with different bytes, so it is specified here. It MUST
be 32 bytes from a cryptographically secure random source, drawn once when the wallet is
created, and it MUST NOT be derived from `spending_seed` or from any other spending or
viewing material. Two reasons, and the second is why the prohibition is a MUST: a sender need
not be a recipient at all — a sender that never registers a meta-address has no spending seed
to derive from — and a sender's announcement entropy MUST NOT be a function of
its spending key, which is the coupling every other rule in this document works to avoid.

**`master` and `i` MUST be persisted together, and a wallet that cannot persist `i` MUST draw
a fresh `master`.** This is the failure that makes the rule normative rather than advisory: a
wallet that restarts, keeps `master` and restarts `i` at zero re-derives seeds it has already
published under, which repeats an ephemeral key and links the two payments on chain — the
single outcome this scheme exists to prevent. Resampling `master` is always safe; restarting
`i` under the same `master` never is.

**Binding `schemeId` alone is NOT sufficient, and the reason is a rung outside this
document.** Another `schemeId` in the same registry has three parameter levels which are all
one `schemeId` with a 32-byte announce seed, so one master and one counter produced the
byte-identical ML-KEM message for two payees at different levels — and by the mechanism this
section is about, either payee could then derive the other's one-time address. The reference
implementation carried the same defect, and its own test could not see it, because that test
used two hand-written schemes with hand-picked distinct ids. **The rule is stated here rather
than left to that document because it binds this rung's derivation function, not that one's.**

**Binding the rung name as well is ALSO not sufficient, and it is the tempting half-measure.**
A rung is instantiated over a KEM, and the same rung over two KEMs is two different things
that MUST NOT share a seed stream. Naming the *wrapper* does not distinguish them: the
reference's ciphertext-binding wrapper reports one fixed name whatever it wraps, so every
rung over it collided with every other rung over it, by exactly the mechanism above. `kem_id`
is therefore **structural** — a wrapper embeds the identifier of what it wraps rather than
replacing it — and every component is length-prefixed so that no two nestings serialise alike.

Implementations MUST bind something that distinguishes rungs sharing a `schemeId`, **and
something that distinguishes KEM instantiations sharing a rung.** This rung's canonical name
is **`"schemeId 3 (direct KEM, hybrid)"`**. It is implemented in `crates/per-payment` and
appears in `vectors/section-5.json`, so it is fixed.

The canonical names of the other schemes in the registry are
`"schemeId 2 (direct KEM)"`, `"schemeId 4 (pairwise)"`, `"schemeId 5 (pairwise, hybrid)"`,
`"schemeId 6 (Spirit, level 2)"`, `"schemeId 6 (Spirit, level 3)"` and
`"schemeId 6 (Spirit, level 5)"`. They are listed because distinctness is a property of the
whole set: an implementation cannot check that its own name is distinct from names it does
not know.

The canonical KEM name for the deployed path is `"ML-KEM-768"`, so `kem_id` there is
`0x000000000000000a ‖ "ML-KEM-768"` — 18 bytes.

The `n` bytes are then split, and the split is normative because both halves are secret and a
wrong boundary is silent:

| | `n` | split |
|---|---|---|
| **schemeId 3** | 64 | `ephemeral_seed(32) ‖ encap_seed(32)` |

Key generation is split the same way:

| | total | split |
|---|---|---|
| **schemeId 3** | 128 | `spending_seed(32) ‖ viewing_ec_seed(32) ‖ kem_seed(64)` |

**One other `schemeId` in the registry shares this keygen split. That is not a licence to
share a key**: an implementation MUST derive independent keys per (`schemeId`, `rung`) pair —
not merely per `schemeId`, since one `schemeId` in the registry has three canonical rung
names that this section requires not share a seed stream — and a meta-address registered
under one `schemeId` MUST NOT be reused under another.

**Key generation from one backed-up master — normative.** A recipient holding one 32-byte
`keygen_master` derives each scheme's keygen seed:

```
keygen_seed(schemeId, rung, j) = HKDF-SHA256(ikm  = keygen_master(32),
                                       salt = absent,
                                       info = "pq-stealth/keygen/v1" ‖ u64be(schemeId)
                                              ‖ u64be(|rung|) ‖ rung ‖ u64be(j),
                                       L    = 128 for this rung)

  where HKDF-SHA256 is the COMPLETE RFC 5869 construction:
      PRK = HKDF-Extract(salt = <32 zero bytes>, IKM = keygen_master)
      OKM = HKDF-Expand(PRK, info, L)
```

**`HKDF-SHA256` above means Extract-then-Expand, both steps, and an absent salt means the
32-byte all-zero salt RFC 5869 §2.2 specifies for that case.** An implementation MUST NOT
skip Extract and use `keygen_master` directly as the PRK.

> **This sentence is the highest-value one in this section.** The naming is genuinely
> ambiguous to an implementer working from this document alone: `HKDF-SHA256(ikm = …)` admits
> a reading in which `keygen_master` *is* the PRK and only Expand runs. **That reading
> produces a different `keygen_seed` for every `schemeId` and every rung**, so two conforming
> wallets would derive disjoint key material and neither could see the other's payments — a
> total interoperability failure from a construction both would describe as "HKDF-SHA256".
>
> The word `ikm` was the only thing distinguishing the readings, since IKM is Extract's input
> and a PRK is not. That is too much weight for one three-letter parameter name in a document
> whose whole purpose is that two implementers reach the same bytes, and it is exactly the
> class of defect no amount of testing one implementation against another can surface: a
> reader can take the correct reading, match every byte, and leave the document as the only
> thing wrong.

**`j` is the rejection index and it is present on every path, including the first.** `j = 0`
is the normal case; there is no `j`-less form. The stakes of reading this any other way: two
conforming implementations would derive different meta-addresses from the same backed-up
`keygen_master`, a recipient restoring in the other one would find nothing, and **both would
report success** — the recovery path succeeds under either reading and the rejection branch
fires at roughly 2⁻¹²⁸, so no test suite would ever reach the divergence.

The four parameters are load-bearing in the same way §1.1's are, and each yields a silently
different key if chosen otherwise: the salt is **absent** and an implementation MUST NOT
supply one; `L` is 128 for this rung, not a fixed 32; `rung` is the same length-prefixed
canonical name this section defines for announce seeds, so that two schemes sharing a
`schemeId` cannot collide; and `keygen_master` MUST be independent of the `master` of the
sender-entropy derivation above, since one is backed up and the other is not.

A recipient who backs up `keygen_master` can regenerate every scheme's keys on a new device,
in any order, without recording which schemes were ever enabled — the derivation is a
function of the `schemeId` and the canonical `rung` name.

> **Whether this derivation is obligatory is OPEN, and the level is stated rather than left
> to be inferred from the heading.** A heading can say *normative* while no sentence in the
> section obliges use of the derivation: every MUST here is conditional on already using it,
> and every `per §5` reference elsewhere in this document is about the *announce* seed. A
> wallet could draw this scheme's keygen seed straight from a CSPRNG, conform completely, and
> leave `vectors/section-5.json`'s keygen row a fixture for a derivation nothing obliged.
>
> **An implementation that offers recovery from a backed-up `keygen_master` MUST derive every
> keygen seed by this function, and MUST NOT draw one from any other source.** In the
> four-document set this obligation is conditioned on seed-only recovery, which that set makes
> a SHOULD rather than a MUST — and a per-payment rung has no channel state to replay, so the
> condition is weaker here still. **Whether that MUST ought to be unconditional is the
> author's call** and is listed in `Open before submission`: the unconditional form would make the
> keygen fixture a fixture for an obligation rather than for a permission, and would exclude a
> device that generates keys in place with no exportable master.

**A keygen seed whose `spending_seed` half is not a valid scalar, whose `viewing_ec_seed`
half is not a valid scalar, or which fails the delegation check of §2.1, MUST be rejected —
and rejection advances the index of the (`schemeId`, `rung`) pair that failed, and no other.
It does NOT draw a fresh `keygen_master`.**

`j` starts at 0 and increments on rejection, and **the accepted `j` MUST be recorded with the
backup**, per (`schemeId`, `rung`) pair, because a recovering wallet cannot tell which index
was accepted without re-running the rejection tests — which it can do, since the tests are
deterministic in the derived bytes, so recording `j` is an optimisation rather than a second
secret.

**Drawing a fresh `keygen_master` on rejection would lose funds, which is why the rule is an
index.** Because every scheme's keygen seed derives from that one master, replacing it
changes the keys of **every other scheme** — including one that already holds funds. A
recipient who enables a second scheme months later, hits an invalid derived seed, and
replaces the master abandons the first scheme's keys. Advancing the index of the failed
(`schemeId`, `rung`) pair confines the retry to it, and it is the same shape as the
sender-side retry two subsections above.

The probability of a rejection is roughly 2⁻¹²⁸ per scalar test, so this path is unreachable
in testing and is specified for exactly that reason.

The 64-byte KEM seed is ML-KEM's `(d, z)` pair, which is also the KEM half of the
tracking-key representation — that is what makes a 96-byte tracking key possible rather than
a 2 432-byte one.

**Conformance requires that every declared seed byte can move the meta-address or the
tracking key.** The disjunction matters, because ML-KEM's `z` governs implicit rejection and
legitimately never reaches the public key. A normative table that names dead bytes as
mandated entropy invites a caller to economise on the live ones.

**This is not a hygiene rule; announce-seed reuse is silently catastrophic.** FIPS 203
derives `(K, r) ← G(m ‖ H(ek))` and Decaps recovers `m`. If the same `encap_seed` is used for
two *different* recipients, payee A learns `m`, recomputes the ciphertext against every `ek`
in the public ERC-6538 registry, identifies B's announcement, and derives B's KEM shared
secret as `G(m ‖ H(ek_B))`. On this rung that is not immediately B's payment secret — the
combiner also takes `ss_ec`, which A does not hold — but it is half of it, and the reuse also
repeats `ephemeral_seed`, which repeats `epk` and links the two payments on chain outright.
**A legitimate payee gets a stranger's KEM secret and an observer gets the link.** The
classical analogue republishes an ephemeral public key: loud, and leaking nothing further,
because recovering the scalar is ECDLP.

### 6. Wire formats and registry

Announcements MUST use ERC-5564's `announce()` unchanged. Meta-addresses MUST be registered
via ERC-6538 `registerKeys` with the matching `schemeId`.

**A recipient MAY register more than one `schemeId` and this document requires that they
can.** The set reading is the one the migration in §9 depends on, so it is the specified one.

Implementations MUST NOT accept an announcement whose `schemeId` is outside the set the
recipient registered, **and MUST treat the mismatch as a skip rather than an error**, per
§2.5 and §2.7.

**A recipient's meta-address length differs between the hybrid and ML-KEM-only variants of
this rung — 1 250 against 1 217 — so changing variant changes `schemeId`, and a sender
holding a stale registration has no specified way to learn of it.** There is no revocation
message, no version field and no announcement type for it. **A recipient MUST continue
scanning a `schemeId` it has registered until retirement of that `schemeId` is permitted, and
MUST NOT deregister it before then.** A future revision SHOULD specify a signalling
mechanism.

> **What permits retirement is NOT specified here, and that is a gap rather than a
> permission.** In the four-document set this document is folded from, retirement is
> permitted once no channel the recipient retains under that `schemeId` has had activity
> within an interval the recipient holds — a condition checkable by the party the obligation
> binds, which is the property that makes it a requirement rather than an aspiration. **A
> per-payment rung retains no channels, so that condition is satisfied the moment it is
> asked, and the requirement above binds nothing on this rung.**
>
> This document does not substitute a condition of its own. It could only be a judgment —
> "until no sender still holds a stale registration" is not a test a recipient can run, and
> §8 of this same document rejects exactly that shape: a rule an implementation cannot check
> is not a requirement but an aspiration in normative clothing. **What quantity a per-payment
> retirement condition should be conditioned on is open**, and it is listed in `Open before
> submission` rather than invented here.
>
> The consequence for an implementer, stated so it is not discovered: **a recipient that
> deregisters immediately after re-registering under a different `schemeId` conforms to this
> document**, and a sender holding the stale registration then announces to a `schemeId` the
> recipient no longer scans. Nothing in this document prevents that, and nothing signals it.

*A rule this section deliberately does NOT contain: treating "a downgrade to a weaker
`schemeId`" as an error. That rule would contradict the mandatory skip in this same section
and, since `announce()` is permissionless, would make a stranger's single announcement into a
permanent scan abort. §2.3 gives the full reasoning, including why no ordering over these
schemeIds exists for "weaker" to select on.*

A recipient MAY publish the set of `schemeId`s it accepts and, having done so, MUST skip
every announcement outside that set. That is a set, not an order, and nothing in this
document requires it.

**Field order is normative**, and a schemeId 3 announcement has two fields in `metadata`, so
the wrong order is the same length as the right one — 1 096 bytes either way — and the
length-based skip rule below does not bind it: a scanner reading the fields in the wrong
order sees nothing wrong about the announcement.

1. **The view tag MUST be the first eight bytes of `metadata`**, at `metadata[0..8]`, with no
   exception. That is what makes §2.5's one-line comparison correct.
2. **`metadata` MUST be exactly `view_tag ‖ ct`, in that order**, and an implementation MUST
   NOT reorder the fields.
3. **`ephemeralPubKey` MUST carry exactly `epk`**, and an implementation MUST NOT swap the
   two ERC-5564 fields. Note this cannot be inferred from lengths: **no `schemeId` is
   identifiable by the position of 1 088 bytes**, as the note after the table records.
4. **Every multi-byte integer on the wire is big-endian.** No such integer occurs in a
   schemeId 3 announcement. The rule stands for a future revision that adds one.

**The view tag comes first, and that is a deliberate choice with a reason.** §2.5's scanner
block hard-codes `metadata[0..8]`, so under a ciphertext-first layout a literal implementer
would compare their derived view tag against the first eight bytes of an ML-KEM ciphertext —
a scanner that misses **every** payment to it and reports nothing wrong. Amending the offset
would fix that instance; putting the tag first removes the class, because `metadata[0..8]` is
then correct in every scheme that has a view tag at all.

*The failure got worse when the tag widened, which is worth noting rather than leaving as
arithmetic.* At one byte a misaligned comparison still matched 1 in 256 payments, so a wallet
saw some of its money and a developer had a symptom to chase. At eight it matches none, and
the scanner reports a clean empty scan.

**The announcement shape, and how a recipient tells it apart.** Recognition is by `schemeId`
plus the two field lengths. No discriminator byte is spent, and one MUST NOT be added — the
payload size §7 prices is exactly this one.

| schemeId | section | `ephemeralPubKey` | `metadata` | payload | meta-address |
|---|---|---|---|---|---|
| **3** | §2 | `epk` — 33 | `view_tag ‖ ct` — 1 096 | **1 129 B** | **1 250 B** |

**A length match is not sufficient, and this rung is the one where that bites.** An
announcement whose field lengths match no row for the registered `schemeId` MUST be skipped,
and skipping MUST NOT be an error: `announce()` is permissionless, so an unrecognised
announcement is one addressed to somebody else, and aborting a scan turns a stranger's
announcement into permanent loss of every payment.

But a length match does not identify the row. **Another scheme in the registry — the hybrid
channel rung's first contact — carries the same field in each position at the same two
lengths**, so a (33, 1096) announcement is a schemeId 3 announcement *only because its
`schemeId` says so*. Recognition per-`schemeId` is therefore load-bearing rather than merely
correct, and `tools/derive_sizes.py` asserts this collision and fails on an undeclared one.

**And thirty-three bytes of the right length can still be a non-point** — 33 zero bytes, or
`0x02` followed by 32 `0xff` bytes. `epk` MUST be validated as a curve point, with the tag
restriction of §2.2, *before* it reaches key agreement. Both reference implementations at one
time classified such an announcement as well-formed and then threw on it, one announcement
from anyone costing a recipient every payment.

> **This is the one requirement in this document that its sources do not state, and it is
> marked rather than absorbed.** The four-document set binds `epk` point-validation to the
> hybrid channel rung's first contact by name; it says nothing about this rung's `epk`, and
> this rung's own scanner table names a malformed `ct` and `ek` but not a malformed `epk`.
> That is a gap in the sources rather than a decision: the two announcements are **byte-identical
> in shape** — the same field in each position at the same two lengths, a collision those
> documents declare in terms — so one of the two is required to validate an incoming point
> and the other is not, for no stated reason.
>
> Stating it here is a normative addition, so it is listed in `Open before submission` for
> the author to ratify, together with the matching correction upstream. It is stated rather
> than dropped because the alternative is a specification that hands thirty-three
> unvalidated, attacker-chosen bytes to a scalar multiplication.

**One `schemeId` cannot cover both variants of this rung, and that follows from this document
rather than from preference.** No discriminator byte is spent and one MUST NOT be added, per
above; the two variants have different **meta-address lengths**, 1 217 against 1 250, and
§2.2 requires decoding to reject any other length. A recipient registers one meta-address
under one `schemeId`, so the count is forced. **schemeId 3 is not reserved** — see
`Open before submission`.

**The OLDER external implementation uses different names.** An implementer reading that
codebase against this document requires that mapping, and requires the warning that its
`metadata` field order and its hybrid combiner's input both differ from what is specified
here.

### 7. Cost

Announcement cost, measured as **real standalone transactions** against the real ERC-5564
interface on anvil (`--hardfork prague`), with `gasUsed` read off the receipt. These are
**total transaction gas** — the 21 000 intrinsic and every calldata byte included — so no
convention needs stating. Generator: `harness/announcement/measure.py`; receipts committed at
`harness/announcement/measured.json` and re-derived from the EIP-7623 rule — with no node —
by `tools/check_measured.py`, which ships here and which a reader runs against this
tree. **The CI definition that runs it on every pass does not ship** — it is written for the
repository this document was folded out of — so the re-derivation is one command a reader
issues, not a promise about a pipeline they cannot see.

**The generator lives in this repository**, beside the figures it produces: a figure whose
harness lives somewhere a reader cannot reference is unfalsifiable, which is the arrangement
the numbers rule exists to forbid. Its field lengths are read from `tools/derive_sizes.py`
rather than retyped, because a retyped copy of a wire table can carry a superseded `schemeId`
and a superseded view-tag width while looking complete — a derived table moves the moment the
wire model does.

| schemeId | payload | calldata | execution | gas | floor binds | vs classical |
|---|---|---|---|---|---|---|
| 1 (classical, ERC-5564's own) | 34 B | 292 B | 5 143 | **28 067** | no | 1.00× |
| **3** | **1 129 B** | **1 380 B** | **14 269** | **69 570** | YES | **2.48×** |

> **Both rows are measured.** The measurement regime is withdrawal-not-adjustment: when a
> payload moves (a tag widens, a field leaves the wire), every affected figure is withdrawn
> and re-measured rather than adjusted by the known byte delta, because an adjusted figure
> has no generator.
>
> **`execution` is not charged where the floor binds** — that is what the floor is — so on
> the schemeId 3 row the column is what the EVM did and not what a sender pays. It is
> recovered from an all-zero payload of the same length, which escapes the floor, and the
> harness **validates** that probe rather than asserting it: on a row where the floor binds
> on neither variant, execution is recoverable twice and the two agree exactly, or the
> harness fails.
>
> `tools/check_measured.py` re-derives every total here from `max(21000 + 4·tokens +
> execution, 21000 + 10·tokens)` and checks every payload against §6's wire table, without a
> node, on any tree it is run against. A figure that stops matching its payload fails — which
> is exactly the failure class this table is exposed to whenever the wire moves, and the
> reason the checker exists.

**The EIP-7623 calldata floor binds**, so execution gas is not charged at all — the cost is
data availability, and optimising the announcer buys nothing.

**An absent figure MUST NOT be filled in by interpolation.** A number nobody measured has no
place in a gas column. The registration table below stayed entirely unmeasured under exactly
that rule until a harness ran it, rather than dividing a calldata length by a gas price.

**Registration is priced against the canonical registry itself.** Every row above is an
`announce()` call; a recipient also makes a one-time ERC-6538 `registerKeys` call whose
calldata is the meta-address. The byte counts are §6's arithmetic on the field sizes,
re-derived from FIPS 203 by `tools/derive_sizes.py`; the gas is measured by
`harness/registration` as real first-time transactions — one fresh registrant per row,
Prague — and re-derives from `harness/registration/measured.json`:

| schemeId | meta-address, registered once | vs schemeId 1's 66 B | registration gas |
|---|---|---|---|
| 1 (classical) | 66 B | 1.0× | 115 310 |
| **3** | **1 250 B** | **18.9×** | **964 809** |

**What the measured object is, because for this table it is the whole question.** Registration
cost is dominated by **storage**, and how much storage depends on how the registry lays the
value out — which this document does not specify and MUST NOT assume. A figure derived from a
storage model nobody has read off a receipt is the wrong instrument. So the harness measures
no model and no recompilation: it installs the **canonical ERC-6538 registry's deployed
runtime bytecode** — read off mainnet at `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538`,
SHA-256-pinned, committed beside the harness — and reads `gasUsed` off the receipts. Each row
is a FIRST registration (every slot zero → nonzero, the "registered once" cost);
re-registration overwrites nonzero slots and costs less, and is deliberately not priced. The
payload fill is all-nonzero, and that is a stated convention rather than a neutral choice:
byte values reach *storage* cost only through all-zero 32-byte slots, which real key material
produces with probability ~2^-256 — but each zero byte in *calldata* is charged 12 gas less,
and real key material has one in roughly 256. So each figure is an upper bound that a real
registration undercuts by a few hundred gas, not an exact cost.

**What the ratio does say, and it is the reader's point.** Registration is once per recipient
per `schemeId`, not once per payment, so an 18.9× calldata multiple on a single lifetime
transaction is a different kind of cost from the announcement multiple — which is why the two
tables are separate. The 18.9× above **is** a comparison against the classical rung, and is
meant as one; what it is not is a per-payment figure, and reading it as one is the single way
to get this table wrong.

**This table prices announcements only, and a payment is not an announcement.** Every row
above is one `announce()` transaction including its own 21 000 intrinsic; **none of them
moves value.** The reference funds a stealth address with a separate transfer carrying empty
calldata, so a payment costs two transactions, and a sender batching the transfer alongside
makes it one.

**A whole payment IS measured, and the figure is 111 510 gas.** `harness/payment/` runs all
three transactions against a local node — announce, fund the derived address, then spend from
it with the derived key — and commits the receipts at `harness/payment/measured.json`:

| | announce | fund | spend | total |
|---|---|---|---|---|
| **schemeId 3** | 69 510 | **21 000** | **21 000** | **111 510** |

> **Its announcement is 69 510 and the table above says 69 570, and the 60 gas is real.** The
> two harnesses fill the announcement payload differently and the EIP-7623 floor binds on both,
> so byte VALUES move the total: a zero calldata byte is one token, a nonzero byte is four. The
> announcement table's harness fills the payload all-nonzero, which is the **worst case** and
> the convention that table states; the payment harness sends the actual derived ciphertext and
> view tag, which happen to carry two more zero bytes — 6 tokens, 60 gas.
>
> **So neither figure is wrong and they measure different things.** 69 570 is the upper bound
> any schemeId 3 announcement can cost; 69 510 is what one particular announcement, derived
> from the fixed demonstration seed, actually cost. A real announcement's payload is
> pseudorandom, so it lands a few tens of gas below the bound with overwhelming probability.
> **Quote 69 570 as the cost of an announcement** and 69 510 only as one measured instance.

**The funding transfer is exactly the 21 000 intrinsic**, because a native-ETH transfer to an
EOA carries empty calldata and touches no contract. The same is true of the sweep. So for
native ETH there is nothing above intrinsic to measure on either side of the announcement,
and the announcement is the whole of this rung's cost above a classical transfer. **For any
other asset it is not**: an ERC-20 transfer and an ERC-20 sweep both execute contract code,
neither is measured by this harness, and neither figure is quoted anywhere in this document.

**The "vs classical" column MUST be read as announcement-to-announcement, and MUST NOT be
quoted as a per-payment ratio.** The reason is that no measured classical *per-payment* row exists —
`harness/payment/measured.json` has no schemeId 1 case — so the denominator of a per-payment
ratio is unmeasured. The omission of the funding transaction from the announcement table is
uniform, so the **ordering** of those rows survives it; a **ratio** does not, because a
constant added to both sides moves it toward 1. Restoring the ratio is one measurement — a
schemeId 1 case in the same harness — and it is listed with the other open items.

### 8. Operational requirements — normative

Cryptographic unlinkability is necessary and not sufficient. A conforming wallet MUST
implement countermeasures for the following:

| | heuristic | requirement |
|---|---|---|
| H1 | same-entity withdrawal | MUST withdraw to an address the wallet generated for this withdrawal and has not previously used, published or registered |
| H1a | — | **and H5 below MUST NOT be read as forbidding that destination** — every H1-compliant destination is an address the wallet controls |
| H2 | gas-price fingerprinting | **non-normative guidance — see below** |
| H3 | timing correlation | SHOULD delay a random 6–24 h before spending |
| H4 | funding linkability | SHOULD fund gas via an ERC-4337 paymaster or relayer |
| H5 | self-transfer | **When spending a stealth address**, MUST refuse a transfer whose destination is **in the wallet's own accounts list** — an account the user holds and transacts from. It MUST NOT be read as covering every address the wallet has *derived*: a scanner derives a candidate address for any announcement whose tag matches, and refusing transfers to those would refuse transfers to strangers. Scoped twice: the destination set, and the transaction — an unscoped *transaction* would forbid every ordinary internal transfer, including the consolidation out of an H1 destination. It binds on the spend path only |

**Every rule above is checkable by a wallet without a chain query.** The requirement is that
a conformance target exist, so a rule an implementation cannot test is not a requirement but
an aspiration in normative clothing. The intuitive forms of these heuristics all fail that
bar, and each row above stands where one of them cannot:

- **"An address with no on-chain history" (the intuitive H1) is undefined**, and the only way
  to discharge it is the global-state query this section warns against two subsections
  below — so a wallet complying would tell an RPC provider precisely which fresh address it
  was about to use. The property actually wanted is *freshness*, and a wallet knows with
  certainty which addresses it generated and published. The normative form is local, exact,
  and strictly stronger for the addresses a wallet is responsible for.
- **"The block's [25th, 75th] percentile" (the intuitive H2)** is a percentile of an unstated
  quantity, in a block that does not exist when the transaction is signed. A usable form
  names the quantity (base fee), the window (the last 20 observed blocks) and the statistic,
  so two implementations randomise over the same interval.
- **"Refuse a self-transfer" (the intuitive H5)** does not say whose. A wallet cannot
  generally know which addresses its *user* controls — a hardware wallet, a second wallet,
  their own exchange deposit address — and MUST NOT be held to that. It does know its own
  **accounts list**, which is the testable core — and **not** every address it has derived,
  per the H5 row above.

**H6, "round to a standard denomination", is guidance below rather than a normative row**: no
standard denomination exists to round to, and inventing one in this document would create a
fingerprint of its own rather than remove one.

**H2 is also guidance rather than a normative row, and for a harder reason: as a rule it
selects a fee the chain would often reject.** Randomising *the gas price* within the
interquartile range of recent **base fees** fails twice. Base fee is not a settable field —
`maxFeePerGas` and `maxPriorityFeePerGas` are — and during any sustained fee rise the
interquartile range of the last twenty base fees lies strictly below the next block's base
fee, so a compliant transaction is not includable. And the same-interval argument fails too:
a window of blocks **a wallet has observed** is per-wallet, and without a stated quantile
method two implementations do not randomise over the same interval. Making it normative needs
a fee field, a quantile rule and an observation window — three more constants for a heuristic
whose effectiveness nothing here measures. It is guidance below.

**Non-normative operational guidance.** These are worth doing and no conformance test is
claimed for them. **Vary the fee you offer** rather than reusing a wallet-default that
identifies your software, noting that a fee below the next block's base fee is not includable
at all, which is why this is guidance and not a requirement. **Round payment amounts** where
the application permits it, since a unique amount links a payment to its withdrawal more
reliably than any other single signal — but note that an amount which is unusual *for the
denomination set in use* is itself a fingerprint, so this helps only where enough
participants round the same way. **Prefer destinations whose prior activity is unrelated to
the recipient's identity**, which is the residue of H1 that a wallet cannot check locally and
a user often can.

**Attribution and evidence, stated precisely.**

- **The 48.5% is Kovács and Seres's**, and it measures **four** heuristics, not these (48.5%
  Ethereum, 25.8% Polygon, 65.7% Arbitrum, 52.6% Optimism). It is real, deployed-data
  evidence that stealth-address operational leakage is material — which is why this section
  is normative — but it does **not** measure this table.
- **The decomposition above is our own**, derived from that work and extended — four
  normative rows, with H2 and H6 as guidance below; the attribution point holds either way,
  since **no deployed-data measurement of any of the six exists** in either form.
- Any effectiveness figure quoted for them MUST carry the word **synthetic**: the available
  "84.5% → 0%" result is over 1 000 *generated* transactions under hand-assumed
  distributions, its 84.5% is dominated by one generator assumption (a hard-coded 70%
  known-address gas-funding rate), and its 0% is structurally guaranteed because the
  mitigated arm constructs transactions in which no critical heuristic can fire. **It is not
  a true-positive/false-positive rate and none exists for this domain.** Do not quote it in
  this document.

Wallets MUST additionally spend a stealth address in full by default — a partially-spent
address links to its successor — MUST NOT reuse a stealth address as an EOA, and MUST warn on
residual balances and outstanding approvals.

Wallets SHOULD defer or batch balance queries for view-tag hits. **At the eight-byte view tag
of §1 a scanner produces essentially no bogus addresses, so every query it makes is about a
real payment** — which makes this requirement more important than it was, not less.

**The observer of that leak was never named, and the leak is larger than batching fixes.**
Asking for the state of a derived address — by `eth_getBalance`, or by a log filter keyed to
it — tells whoever answers that the asker cares about that address. A wallet that queries
only what it matched has a query set equal to its payment set, so **the party serving the RPC
learns the recipient's payment graph**: the same thing §9 records a delegated scanner
learning, except that a delegated scanner is a chosen trust assumption and an RPC provider
usually is not. Deferring and batching smear the queries in time; they do not remove the
association.

Two things follow that a wallet author needs stated:

- **The cover traffic is absent, deliberately, and this is where its absence lands.** A
  one-byte view tag admits 1 in 256 foreign announcements, and those false positives can be
  argued to be cover for the queries that matter. §1 records why that argument does not
  survive implicit rejection — the noise did not prevent the disclosing query, it made one
  necessary — and §2.8 carries the withdrawal. **What follows for a wallet author is that
  deferring and batching are now the only mitigation in this document**, where before they
  sat on top of a noise floor.
- **The premise was never a constant even when it existed.** The mitigation assumed bogus
  addresses arrive at 1/256. Per §2.6 anyone can publish an announcement a scanner accepts,
  so the rate of *matching* announcements was attacker-settable at one announcement each.

**Private retrieval is out of scope for this ERC.** Reading chain state without revealing
which state is read — private information retrieval, or oblivious message retrieval — is the
primitive that would close the paragraph above, and it is deliberately not specified here.
Two reasons. It is **not specific to stealth addresses**: any protocol whose recipient
locates its own items in a public log has the same problem, and a solution belongs at that
layer rather than inside one address-derivation scheme. And it is **a research programme
rather than a requirement**: the trade it resolves is a three-way one — confirm value
arrived, do not reveal which address is of interest, do not compute all state locally — of
which a wallet today picks two, a full node buying the first two at the cost of syncing. A
future revision MAY reference such a layer once one is specified; this document MUST NOT be
read as providing it.

### 9. Security considerations

**KEM anonymity is REQUIRED and the argument for it is derived, not cited.** The public
ERC-6538 registry gives an adversary every candidate encapsulation key, so a ciphertext
linkable to its key deanonymises every payment without decryption. ML-KEM-768 is ANO-CCA by
composing Bao–Pan (ePrint 2026/396) Thm 4 — wANO-CCA\*, in the **ROM** — with their Lemma 1
and FIPS 203's IND-CCA2 claim. **Bao–Pan do not state this result**; the composition is this
specification's. QROM is open and the authors name it so.

The chain, with what each step actually assumes:

| step | gives | assumes |
|---|---|---|
| Bao–Pan Thm 4 | wANO-CCA\* of ML-KEM-768 | ROM; `J` a secure PRF; the underlying PKE δ-correct and γ-spread; **wANO-CPA** and OW-CPA of that PKE; collision-resistance of `F(pk)` |
| Bao–Pan Lemma 1 | wANO-CCA + IND-CCA ⇒ ANO-CCA | standard model, tight in advantage, time and memory |
| FIPS 203 | IND-CCA2 of ML-KEM-768 | stated there as a **belief**, not a theorem |

So the composition is short and most of it is theirs — Theorem 4 is about ML-KEM-768
standalone. **What is not discharged is wANO-CPA of the underlying K-PKE**, which Theorem 4
reduces to and no cited source proves. It is widely believed for K-PKE. A reviewer asking
which hardness assumption announcement unlinkability rests on does not get an answer from
these citations, and that is the likeliest question this section will face.

*One consequence worth recording, since this rung IS a hybrid and hybridisation has been
discussed as a remedy: it is not one for this gap.* Bao–Pan's own X-Wing result **consumes**
ML-KEM-768's weak anonymity as a hypothesis rather than removing it, and discharges it with
the same Theorem 4 — so the undischarged premise sits underneath the hybrid and the
standalone argument alike. Their X25519 half is proven without a hardness assumption, which
is what a hybrid genuinely adds: an unconditional addend, not a substitute.

**A delegated scanner learns the recipient's entire payment graph.** It cannot spend. It sees
every payment, their timing and their count. **That is the cost of delegating discovery — the
tracking key — and it is the only grain this rung has.** A per-payment rung offers no finer
one: the tracking key is all-or-nothing over the recipient's whole payment history.

**A quantum adversary combined with one scanner takes everything.** ERC-6538 publishes the
master spending public key permanently; a CRQC recovers `spending_sk` from it, and a scanner
holds every `ss`. `stealth_sk = spending_sk + H(ss)` then yields every one-time key, past and
future. **The scanner-cannot-spend property holds only against a classical adversary.** This
scheme makes announcements post-quantum and leaves funds on ECDSA.

**This rung therefore expires at a CRQC, and that fixes what its hybrid half is for.** This
is the author's framing. Spending is secp256k1, so once a CRQC exists the rung is not a
usable scheme whatever its announcement layer does: the funds are already gone by the
paragraph above. It follows that **the EC half is not post-quantum protection of anything** —
by the time the quantum adversary arrives there is nothing left for it to protect.
Implementations and documentation MUST NOT present it as post-quantum protection.

What the hybrid is for is the interval **before** a CRQC exists: it keeps the guarantee
already in production as a floor under a primitive whose implementations are new. The
author's emphasis is **implementation risk** — a defect in an ML-KEM implementation costs
privacy today rather than in a decade — and the general form is any pre-CRQC failure of
ML-KEM's confidentiality or anonymity, of which implementation defects are the likeliest and
classical cryptanalysis the other.

**So the hybrid is an engineering control, and it MUST be justified as one.** That has a
consequence worth stating where the decision gets made rather than leaving it implicit: other
controls address the same risk, and they are not priced against each other anywhere in this
document. Two independent implementations checked against one fixture set and the FIPS 203
ACVP vectors both reduce implementation risk directly; a formally verified ML-KEM reduces it
at the source. This rung costs 33 bytes on every announcement, permanently, plus a scalar
multiplication on every announcement scanned, and covers what those do not — a defect the two
implementations share, or one below the level the vectors reach. A future revision SHOULD
state which of these it relies on rather than adopting the hybrid by default.

**The hybrid is temporary, and the schedule is recorded rather than left to a reader.** The
author's decision: deploy the hybrid variant now, move to the ML-KEM-only variant when the
classical half is no longer permitted, and add post-quantum spending at that point. So
schemeId 3 is the deployment target today and the ML-KEM-only variant is the target after the
transition rather than a demonstration. Implementations MUST NOT read the ML-KEM-only variant
as deprecated; it is the destination.

**What fixes the date, from the primary source.** NIST IR 8547 Table 4 places elliptic-curve
Diffie–Hellman at **"Disallowed after 2035"** for parameters at 128 bits of security strength
or above. secp256k1 is in that row, **not** in the 112-bit row that carries the additional
"Deprecated after 2030" — so the date that governs the EC half of this variant is 2035, and
quoting 2030 for it would be wrong. NIST's own framing of hybrids matches this schedule in
terms: they are *"typically expected to be temporary measures that lead to a second
transition to cryptographic tools that use only PQC algorithms."* Note this is a US federal
transition timeline and is not binding on Ethereum; it is cited because it is the only
published schedule with dates attached, and because the second transition it describes is the
one this ladder is built to make cheap.

**That source is an Initial Public Draft and this document MUST cite it as one.** Confirmed
against NIST's own publication page: the draft is dated 12 November 2024, its comment period
closed 10 January 2025, and the document history shows no final version. So the 2035 date is
what a draft proposes and is subject to change, and the schedule here **follows** it rather
than being fixed by it. *A caution that bears on checking these citations: secondary
summaries of this document circulate with a wrong publication status and a reversed account
of its position on hybrids — only the primary source is cited here, and only the primary
source settles a disagreement with it.* SP 800-227, the other NIST citation, **is** final —
September 2025.

**One consequence for the reader who stops here.** A wallet that ships only this variant has
a migration ahead of it in which the *meta-address length changes* — 1 250 to 1 217 — and
therefore the registered `schemeId` changes, per §6. That is the migration this ladder's
shape exists to make mechanical, and it is why both variants of the rung are specified,
though only one of them here.

**The concatenate-then-derive shape is the approved composite, not an invention.** NIST SP
800-56C admits a shared secret of the form `Z' = Z ‖ T` where one part comes from an approved
key-establishment method, and SP 800-227 approves that combiner for any number of secrets
provided at least one comes from an approved method or an approved KEM, naming FIPS 203's
output as qualifying. §1.1's IKM is that construction. What is **not** settled is which
additional inputs belong beside the two secrets — see the note in §1.1.

**A leaked one-time key plus `ss` yields the master spending key.** Inherited from ERC-5564,
not introduced here.

**A leaked one-time key *alone* yields nothing, and the reason it does is structural** — the
two hazards sit side by side and differ for a stated reason. `stealth_sk = spending_sk +
H(ss) mod n`, and `H(ss)` is a scalar essentially uniform on `[1, n)`. So a one-time key is
the master masked by a **one-time pad over the full scalar field**: it is uniform, it reveals
nothing, and *k* disclosures reveal nothing, because each carries an independent uniform mask
and there is no intersection to take. The hazard above needs a **second** secret, `ss` — and
in the expected deployment the two sit with different parties, the wallet holding the key and
a delegated scanner holding every `ss`.

> **This property is a consequence of the group, not of stealth addresses**, and it does not
> survive a change of signature primitive. A rerandomised-key stealth address built over a
> lattice signature has a *short* mask rather than a uniform one, a short mask is a bounded
> mask, and a bounded mask leaks: each disclosure narrows rather than hides, and narrowings
> intersect. It is noted here so that a wallet author who later adds such a rung does not
> carry this rung's intuition — that derived keys are low-value artifacts fit for backup,
> logs and export — across to it, where the intuition is wrong and the failure is silent.

**The exact view tag is a distinguisher, and this document resolves that in its favour.** The
tag is a *positive* test, and a positive test is by construction a distinguisher: it tells
whoever can observe the outcome that this announcement was for this recipient. ML-KEM's
implicit rejection exists precisely to withhold that signal, so an exact tag hands the layer
above what the KEM declined to give — at 64 bits, exactly. The KEM property is not broken; it
is bypassed. The resolution is in the tag's favour, because the alternative — a narrow tag —
does not spare the recipient the disclosing chain-state query but *obliges* one, per §1.
**Implementations MUST NOT assume the reverse ordering is safe**, and §8's countermeasures
are written for the observable side.

**An RPC provider is an unnamed party in this threat model.** A recipient who confirms a
payment by asking for the state of a derived address discloses to whoever answers that the
address is of interest, and a wallet querying only what it matched has a query set equal to
its payment set. That party then learns what the delegated scanner above learns. §8 states
the countermeasure and its limits; the point here is that this party belongs on the list — an
enumeration without it undercounts who learns the payment set.

**One composition of two stated rules deserves its own paragraph.** Recognition is by
`schemeId` alone — the shape identity between a schemeId 3 announcement and the hybrid
channel rung's first contact leaves no other separator — and §2.3 requires a scanner to skip
every announcement whose `schemeId` the recipient did not register. Together: a sender that
emits correct bytes under the wrong `schemeId` creates payments that no conforming scanner,
live or rescanning, will ever surface, because the skip is by id, not by content. The funds
sit at addresses the recipient's keys control and only deliberately non-conforming tooling
can find. For a sender library, the `schemeId` argument is interoperability-critical output,
not metadata — the chain accepts the announcement either way; conforming scanners are what it
decides.

## Rationale

Why the specified design and not the obvious alternatives. Every entry here corresponds to a
decision with a date; where the reasoning came from a primary source rather than from
preference, the source is named.

**Two `schemeId`s for this rung rather than one with a variant field.** A single id with a
discriminator byte was rejected because recognition is by `schemeId` plus field length, and
the two variants have **different meta-address lengths**, 1 217 against 1 250. A recipient
registers one meta-address under one id, so the count is forced by the decoder rather than
chosen for symmetry.

**The view tag is `metadata[0..8]`, with no exception.** Without this rule it would sit at
offset 0 in one announcement shape and 1 088 in another, and a sentence telling a scanner to
compare "the first byte of `metadata`" would have an implementer on this rung comparing
against the first bytes of an ML-KEM ciphertext and missing payments silently. Moving the
field costs nothing — same bytes, same length — and removes the class of defect rather than
the instance.

**The width is eight bytes and not one, and the reason is ML-KEM's implicit rejection.** §1
carries the argument. The short form is that a KEM which never fails gives a scanner no
signal of its own, so the tag is the only signal, and a narrow tag does not spare the
recipient a disclosing state query — it obliges one. The cover traffic a 1-in-256 rate was
said to provide needs an observer of the queries to be covered from, and the deployments this
document describes are a recipient scanning their own node, where there is none, and a
delegated scanner, which already holds the whole payment graph.

**The hybrid combiner is the shape NIST SP 800-227 puts forward.** Not for conformance — this
is not a NIST protocol — but because §4.6.3 of that document holds that a combiner over the
two shared secrets alone does not preserve IND-CCA regardless of the KDF, which is precisely
the failure this variant exists to hedge. The two added inputs, `ct` and `viewing_pk_ec`, are
already on the wire or in the registry, so announcements do not grow. `ek` is redundant —
FIPS 203 Algorithm 17 binds `H(ek)` into the KEM's own shared secret — and is included so the
shape needs no argument to accept. **X-Wing was considered and declined**: its draft is an
Independent Submission with no IETF standing, and adopting a third party's combiner would
have imported a versioning dependency for no property the above does not give.

**The hybrid is temporary, and the schedule is NIST's.** This rung spends on secp256k1, so a
CRQC ends it whatever the announcement layer does; the EC half is therefore not post-quantum
protection but cover for the interval before a CRQC exists, where an implementation defect in
ML-KEM is the likeliest failure. NIST **IR 8547 ipd** Table 4 places elliptic-curve key
establishment at ≥128 bits of security strength as **disallowed after 2035** — not the 2030
date, which applies only to the 112-bit row — and states that hybrid solutions "are typically
expected to be temporary measures that lead to a second transition to cryptographic tools
that use only PQC algorithms." So this rung is the near-term deployment and the ML-KEM-only
variant is the destination, which is the opposite of what a reader would assume from the id
order.

**The delegation check scans the whole delegated object, not each half.** With a 128-byte
keygen seed the delegated object is a 96-byte concatenation with 65 window positions, of
which per-half scanning covers 34. The 31 straddling positions place the spending seed
verbatim in bytes handed to a scanning service and pass a per-half check. An earlier
formulation stated the rule for a single-secret tracking key and put the "delegated object is
the pair" reasoning only in the rationale beside it, so two conformant implementers would
have disagreed — one reading the rule, one reading its justification.

**A `schemeId` mismatch is a skip and never an error, and "weaker `schemeId`" is undefinable
rather than undefined.** `announce()` is permissionless, so any error path is a permanent
scan abort a stranger can trigger for one announcement's gas. And no order over the
registry's schemeIds exists to appeal to: the ML-KEM-only per-payment rung has per-payment
forward secrecy and no classical floor, the hybrid channel rung has the floor and no forward
secrecy, and neither is weaker than the other. An ordering invented in order to apply a rule
is not a rule.

**Value confirmation is a SHOULD.** A MUST would make conformance depend on chain access
beyond the announcement log, which nothing else here requires. The asymmetry is stated in the
text because an implementer will otherwise discover it: an ERC-20 transfer emits a log a
scanner already reads, and a plain ETH transfer emits nothing, so the two asset types need
different mechanisms.

**The announced-address comparison is a MAY, and its justification is withdrawn.** It filters
a phantom announcement for free. The argument for the MAY also claimed it removes the cover
traffic a 1-in-256 view-tag false-positive rate provides — and the view tag is now eight
bytes, so that cover does not exist and the comparison has no cost to weigh against its
benefit. §2.8 carries the withdrawal in full and records the consequence: the level is now
under-justified, and raising it is a question for the author rather than something this
document decides.

**An announcer forwarding value is out of scope rather than prohibited.** Permitting it
properly means modelling a party who knows both the announcement and the source of funds,
which is a threat-model section rather than a sentence. Recorded as scoped out so the absence
is legible.

**Two operational heuristics are non-normative guidance, and two are testable requirements.**
H2 and H6 are guidance; H1 and H5 are requirements, and **stronger** than their intuitive
forms. Each of the four, in its intuitive form, is a normative requirement with no
implementable test: "no on-chain history" is undefined and checkable only by the global-state
query §9 warns against; a gas-price percentile is of an unspecified quantity in a block that
does not exist at signing time; a wallet cannot generally know which addresses its user
controls; and there is no standard denomination. A conformance target containing unreachable
requirements is worse than one that admits the gap.

## Backwards Compatibility

**No consensus change, no new opcode, no change to ERC-5564 or ERC-6538.** This scheme uses
`announce()` and `registerKeys` unchanged, and adds nothing to either interface. The
`schemeId` field exists precisely to carry schemes these standards did not anticipate.

**One `schemeId` value awaits reservation** — 3. It is not reserved today; see Open before
submission.

**Existing schemeId 1 deployments are unaffected, and the skip rule is why.** A wallet that
supports only schemeId 1 encounters these announcements in the same event stream and skips
them on `schemeId`, which is mandatory behaviour rather than a courtesy. Nothing in this
document changes the meaning of an existing announcement, an existing meta-address, or an
existing registration, and the registry is keyed by `schemeId`, so registration under 1 and
under 3 coexists with no migration.

**Nothing DEPLOYED is affected, because nothing is deployed.** The older external
implementation of this scheme derives a different `metadata` field order and a different
hybrid combiner IKM than this document specifies — every payment secret it derives differs —
and that costs nobody anything: no deployment exists, no `schemeId` is reserved, so nothing
external depends on any divergent form. The conformance fixtures exist and ship, so a change
that moves a pinned byte costs a fixture revision that says so out loud.

**One forward-compatibility obligation is created here, and partly discharged.** Per the
Rationale above, schemeId 3 is intended to be retired in favour of the ML-KEM-only variant by
the NIST date. A wallet implementing only this variant faces adding the other one; a wallet
implementing both is unaffected. §6 requires that a recipient MAY hold several registrations
and MUST continue scanning a registered `schemeId` until retirement of it is permitted.
**What is absent is both halves of that.** There is no signalling — no message by which a
recipient tells a sender its `schemeId` changed — and on a per-payment rung there is no
channel-activity quantity for a retirement condition to be conditioned on, so nothing here
says when retirement becomes permitted. §6 states the rule, the gap and where the decision
sits; a recipient that deregisters immediately conforms.

## Test Cases

**Fixtures exist and ship** — `vectors/section-*.json`, with a sha256 each in
`vectors/manifest.json`, regenerable and checkable with
`python3 tools/gen_vectors.py --check --wave 1`. `vectors/PLAN.md` carries the row list the
generator reads and, per row, the normative sentence it pins.

**Thirty-seven rows pin this rung**, and they are four groups rather than one, which is worth
stating because a reader expecting a single `schemeId 3` file will not find one:

| group | rows | what it pins |
|---|---|---|
| `vectors/section-1.json` | 7 | §1 — the offset derivation, the counter-reduction retry, the big-endian reading, the view tag |
| `vectors/section-2.json` | 13 | §2's shared half — everything from `ss` onward, which this rung shares byte-for-byte with the ML-KEM-only variant |
| `vectors/section-2_9.json` | 12 | this rung's own four deltas — the 128-byte keygen seed, the 1 250-byte meta-address, the 64-byte announce seed and the combiner, and the wire mapping |
| `vectors/section-5.json` | 5 | §5 — the sender-entropy and keygen derivations, including this rung's canonical name |

**Why 37 and not 12.** This rung's conformance is not its deltas alone: the shared half is
pinned by §2's rows and the common definitions by §1's. The four file names carry the section
numbering of the four-document set — `section-2_9` in particular names a section that this
document dissolved — and they are **not** renamed here, because renaming a published fixture
file breaks every manifest sha256 and every runner that reads it. The mapping is in the table
above and each row cites both numbering schemes.

**Each fixture row carries the normative sentence it pins and the wrong output it
distinguishes** — the second half being the part that makes a vector worth having. The
fixtures were written before the code they check, and every wire decision above was cheaper
to take then than after.

**Not all of them are executed.** Fewer rows are drivable than exist: some pin an intermediate
that a conforming implementation is not obliged to expose. Each such row says so in place.

**The conformance RUNNER is not part of this export**, because it drives the fixtures of every
rung in the registry and depends on the crates implementing them — shipping it would put the
other schemes back into a tree whose reason for existing is that they are absent. What ships
instead is the generator. **That is not the better of two things, it is one of two things**,
and the note below the tier table says why the pair is easy to conflate: the generator settles
where the expected outputs came from, a runner settles whether an implementation produces
them. Neither answer substitutes for the other. This tree carries the first and not the second.

The full vector plan has three tiers. Two of them bear on this document, and only one is ours
to produce:

| tier | what it covers | source |
|---|---|---|
| 1 | ML-KEM-768 itself | **NIST ACVP files, vendored at a pinned revision.** We generate nothing |
| 2 | **this document's layer** — the derivations, the wire formats, the skip tables, the retry paths | ours, and the one to write first |

**Tier 3 is deliberately absent from that table and not an omission.** It is parity against the
Spirit authors' C, which is evidence for the post-quantum *spending* rung and not for anything
in this document. It stays separate, in both senses: separate vectors, and outside the scope of
this specification.

**Two properties of the tier-2 generator are requirements rather than preferences.** It MUST
import nothing from the reference implementation, because a fixture derived from the code it
validates tests only self-consistency. And a conformance runner MUST be callable by a third
party against their own implementation without reading ours, which is what makes "a third
implementer can build from this text" a checkable claim rather than an assertion.

> **The second of those two is a requirement this tree does not satisfy, and the distinction
> matters because the two are easy to conflate.** The generator's independence is a property
> of where the fixtures came from, and it holds: `tools/gen_vectors.py` derives them from this
> document's prose and reads nothing from the reference implementation. **A runner is a
> different thing** — it executes somebody else's implementation against those fixtures and
> reports — and no such runner is present here, because the one this project has drives every
> rung in the registry and depends on the crates implementing them. A third party checking
> their own implementation against these fixtures writes that driver themselves; the fixtures
> and this document are what they need to, and the requirement above says what the conformance
> target must eventually provide.

**What no fixture can reach is stated in the plan rather than left implicit** — keygen
determinism across processes, announce-seed non-reuse, and constant-time behaviour, which
this document does not specify anywhere. Those need a harness or a type system, not a vector,
and the vector set MUST NOT be read as covering them.

## Reference implementation

**schemeId 3 is implemented alongside this document**, in `crates/per-payment` over
`crates/kem`, `crates/ec` and `crates/core`. Those four crates are the closure of this rung's
dependencies: nothing else is needed to derive a key, build an announcement or scan for one.

**That crate implements both variants of the rung, and that is conformance rather than
mixing.** §2.8 requires that the code from `ss` onward be shared rather than duplicated; a
crate carrying only this variant would duplicate that half and violate the requirement. The
crate is one module generic over the variant, so the claim that the two differ only in the
ECDH half is checked by the code compiling for both.

The announcement-gas harness that produced §7's measured row is `harness/announcement/`,
`harness/registration/` measures the registration row, and `harness/payment/` measures all
three transactions of a payment against a local node.

**Unreviewed.** Nothing here has had external cryptographic review, and no conformance row
in this export has a witness outside this project — no third party has re-derived any of them.
A number of normative requirements are satisfied by the older external implementation only in
part: design decisions moved the specification ahead of that code. They are port obligations,
not defects.

*Repository visibility was not confirmed when this section was written — the environment it
was written in had no credentials for these remotes. A submitter MUST confirm the repository
is public before citing it in a published ERC.*

## Security Considerations

**§9 above is the security considerations section**, and it is normative in the parts that
carry RFC 2119 keywords. It is numbered §9 rather than appearing here unnumbered because the
section numbering is shared with the four-document set this specification is folded from; see
"Relationship to the four-document set".

## Copyright

Copyright and related rights waived via [CC0](../LICENSE-CC0).

## Open before submission

1. **Reserve schemeId 3** with the ERC-5564 authors. It is not reserved today.
2. **Assign an editor.** Unassigned.
3. **Conformance target** — what an implementation MUST pass to claim support.
4. **A wallet team's integration signal.** None yet.
5. **The announced-address comparison's normative level.** It is a MAY, and the trade that
   once justified the MAY no longer exists: with the eight-byte view tag the comparison is
   free on both sides. §2.8 records this. Raising it to a SHOULD is a normative change and is
   the author's, not this document's.
6. **A per-payment retirement condition — the requirement in §6 currently binds nothing.**
   §6 says a recipient MUST keep scanning a registered `schemeId` until retirement is
   permitted, and the four-document set makes retirement permitted once no retained channel
   has had recent activity. A per-payment rung retains no channels, so that condition holds
   immediately and the requirement is vacuous here: **a recipient that deregisters at once
   conforms**, and a sender holding the stale registration loses the payment. What quantity a
   per-payment condition should name is open. Listed rather than decided because the only
   substitute available without a new measurable quantity is a judgment — "until no sender
   holds a stale registration" — and §8 rejects that shape in terms.
7. **A measured classical per-payment row**, so §7's "vs classical" column can be quoted as a
   per-payment ratio rather than only announcement-to-announcement.
   `harness/payment/measured.json` measures this rung and the ML-KEM-only variant but has no
   schemeId 1 case, so the denominator is unmeasured. One harness case, not a redesign.
8. **An ERC-20 measurement.** §7's payment figures are native ETH, whose funding transfer and
   sweep are both exactly the 21 000 intrinsic. An ERC-20 payment executes contract code on
   both, and neither is measured.
9. **Ratify §6's `epk` point-validation requirement, or correct the sources instead.** It is
   the one requirement here that the documents this was folded from do not state: they bind
   that validation to the hybrid channel rung's first contact by name, and say nothing about
   this rung's `epk` — although the two announcements are byte-identical in shape, a collision
   those documents declare. Either this document keeps it and the common document gains the
   same rule, or the author decides the omission upstream was deliberate and this document
   drops it. It is stated here because the alternative hands thirty-three unvalidated,
   attacker-chosen bytes to a scalar multiplication.
10. **Decide whether §5's keygen derivation is unconditional.** It is currently a MUST for an
   implementation that offers recovery from a backed-up `keygen_master`, and nothing in this
   document makes offering that recovery more than a SHOULD — so a wallet that never offers
   it is free to draw its keygen seed from a CSPRNG and still conform. The unconditional form
   turns `vectors/section-5.json`'s keygen row into a fixture for an obligation and excludes a
   device with no exportable master.
11. **Independent cryptographic review**, particularly of §9's derived anonymity argument.
