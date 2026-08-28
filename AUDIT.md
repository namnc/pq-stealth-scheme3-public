# For an external auditor

TLDR: what has already been checked and by what kind of evidence, and what is not covered.

---

## 1. What this is

A specification and a reference implementation for one post-quantum stealth-address scheme on
Ethereum, extending [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) (announcements) and
[ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) (a registry of meta-addresses) with a new
`schemeId`. A sender pays an address only the recipient can derive; the announcement is public
and must not become linkable to the recipient once a quantum computer exists.

**Spending is ordinary secp256k1 ECDSA.** This rung closes a retroactive hole in the
announcement layer; it does not make spending post-quantum. Read every claim here with that
boundary in mind, because it is the one a reader is most likely to widen on the scheme's behalf.

**No `schemeId` is reserved.**

## 2. What is in scope

1. **The rung, end to end**: `keygen`, `announce`, `bind`, `scan` and `spend_key`, and the wire
   encoding in §6 of the specification.
2. **The `bind` check** — §1's requirement that a scanner recompute `ek` from its `(d, z)` seed
   and compare it against the registry before scanning. A corrupt tracking key is otherwise undetectable: it expands into a
   valid keypair for a different key, and every scan then returns "not mine" for ever, with no
   error anywhere.
3. **The hybrid combiner**, field by field — the order of the inputs, the domain separators, the
   length prefixes, and whether the view tag is a separate digest from the offset.
4. **The fixtures**, and whether each pins its own claims. `vectors/`
   holds four files: `section-2_9.json` is this rung, `section-1.json` and
   `section-5.json` are the primitives and seed derivations under it, and all three are
   reviewable against the specification.
   `section-2.json` is not — see §3 — but it is
   the only one, and it is a quarter of the rows rather than most of them.
6. **The specification text itself.** Ambiguity is a defect here even where the bytes agree:
   two conforming wallets that read a sentence differently derive disjoint key material and
   neither can see the other's payments.

## 3. What is out of scope, stated rather than implied

- **Formal verification.** There is none, of anything, and the specification's trustlessness
  argument asks for it eventually. This is the honest state and not the end state.
- **Constant-time execution.** Nothing here is written for it or checked for it. The scanner's
  comparisons and the combiner's arithmetic are ordinary Rust.
- **The ML-KEM implementation.** `crates/kem` is a thin layer over the `ml-kem` crate, checked
  against NIST's ACVP cases. Auditing that crate's lattice arithmetic is a different engagement.
- **The `secp256k1` implementation.** Likewise `k256`, chosen because it is what the upstream
  reference uses, which matters for the SEC1 compact-tag hazard §2.2 warns about — a different
  curve library would not reproduce the defect the warning is about.
- **Deployment.** Nothing here is a deployment proposal. No contract of ours is on any network,
  and the announcer under `contracts/` is present so the gas harnesses have something real to
  measure.

## 4. Threat model, in one paragraph

The adversary records every announcement and every registry entry today, and acquires a
cryptographically relevant quantum computer later. Against that adversary the question is
whether an announcement can be linked to the recipient who could spend it. The adversary is not
assumed to control the recipient's device or to see the sender's entropy source. `ss` is
SHA3-256 of both shared secrets and the public fields; anyone who has both secrets can
compute it. Which registered `ek` a `ct` belongs to is a question about those public bytes.
The hash is not used for that. Denial of service against a scanner is in scope where the
specification makes a claim about it, which is why the `schemeId`-mismatch rule above is
normative.

## 5. What is already verified, and by what kind of evidence

Evidence is worth what its independence is worth, so it is separated by kind rather than
counted:

- **NIST.** `crates/kem` is checked against ACVP cases nobody here wrote, including all ten
  decapsulation cases.
- **Two implementations.** secp256k1 exists twice in this tree — hand-rolled from SEC 2 in
  `tools/vecprim.py`, and `k256` in Rust. HKDF likewise: the fixtures' generator hand-rolls it
  and the crates use RustCrypto's, so agreement between them is a cross-implementation check
  rather than one author agreeing with themselves.
- **A ledger of blinded independent re-derivation — and read what it is carefully.**
  `vectors/rederivation.json` is a record that a second implementer computed rows from the
  specification prose alone, with no access to the expected values and no elliptic-curve
  library. **Read its classification keys rather than this description of them.** The file has
  seven top-level keys: `_what` and `_source`, which describe it, and five that classify rows.
  `bytes_agree` and `outcome_only` are the two kinds of agreement. `bytes_disagree` is empty,
  and its being empty is the claim that nothing disagreed. `ungeneratable` names a row the
  re-derivation reached and could not compute — a fact about the second implementer's sandbox,
  not about the row. `absent` names a row never attempted at all, and it is **authoritative
  when populated** rather than something to infer by subtracting the others.
  **Every row in this tree is in one of those five**, and that is a checked property rather
  than a promise: the ledger is derived for the fixtures that ship, and the derivation refuses
  to emit one that leaves a shipped row unclassified, so a release cannot be built where this
  sentence is false. Read the file rather than any total quoted about it — including one quoted
  here, which is why none is.
- **Measurement, with the harness committed.** Every gas figure comes from a real transaction
  against a real node, with its receipt in `harness/*/measured.json`;
  `tools/check_measured.py` re-derives the announcement figures from the EIP-7623 calldata rule
  without a node at all. A figure whose generator is absent would be unfalsifiable, which is
  worse than an absent figure.

**What none of that establishes.** The fixtures are generated by the Python in `tools/` and the
crates are tested against the fixtures, so "Rust agrees with Python" is internal consistency and
not correctness. The blinded re-derivation is what converts part of it into evidence, and it
covers the rows the record above names and no others.

## 6. What is provisional, and why — read this before filing a finding about a constant

Some values here are decisions rather than derivations, and the specification marks them. A
constant marked provisional has no outside adopter: this tree's own implementation produces
those bytes and, where the record says so, a blinded re-derivation agreed on them, but nothing
external has committed to the value. **A finding that such a constant is wrong is welcome; a
finding that it is unsourced is already recorded.**

The domain separators, the 8-byte view tag width, the field order of the seed derivations and
the choice of ML-KEM-768 over other parameter sets are all in that class.
