# For an external auditor

Read this first. It says what is being asked of you, what has already been checked and by what
kind of evidence, and — at greater length than is comfortable — what is not covered.

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

**No `schemeId` is reserved.** The specification says so in place. An identifier used here is a
proposal, and a finding that two artifacts in the world claim the same one is a real finding.

## 2. What is in scope

1. **The rung, end to end**: `keygen`, `announce`, `bind`, `scan` and `spend_key`, and the wire
   encoding in §6 of the specification.
2. **The `bind` check** — §1's requirement that a scanner recompute `ek` from its `(d, z)` seed
   and compare it against the registry before scanning. It is the newest argument here and the
   most worth disputing. A corrupt tracking key is otherwise undetectable: it expands into a
   valid keypair for a different key, and every scan then returns "not mine" for ever, with no
   error anywhere.
3. **The hybrid combiner**, field by field — the order of the inputs, the domain separators, the
   length prefixes, and whether the view tag is a separate digest from the offset.
4. **The fixtures**, and whether each pins the normative sentence it claims to. `vectors/`
   holds four files and nothing else: `section-2_9.json` is this rung, `section-1.json` and
   `section-5.json` are the primitives and seed derivations under it, and all three are
   reviewable against the specification you have. `section-2.json` is not — see §3 — but it is
   the only one, and it is a quarter of the rows rather than most of them.
5. **The specification text itself.** Ambiguity is a defect here even where the bytes agree:
   two conforming wallets that read a sentence differently derive disjoint key material and
   neither can see the other's payments. That has happened once already, on an `HKDF-SHA256`
   phrasing that admits a reading in which only Expand runs.

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
- **The sibling rungs, and the one whose fixtures are still here.** The ladder has a
  pairwise-channel pair and a post-quantum *spending* rung. Neither their specifications nor
  their fixtures ship, and `vectors/` — its plan, its manifest and its re-derivation ledger
  included — describes only the files present.
  The KEM-only per-payment variant is the exception, in both directions. Its **code** ships
  inside `crates/per-payment`, because §2.8 requires the code from the shared secret onward be
  shared rather than duplicated. Its **fixtures** ship, in `vectors/section-2.json`, because
  that code would otherwise be shipped untested — and shipping code no fixture reaches is the
  worse of the two problems. Its **specification does not ship**, so those thirteen rows pin
  sentences you do not have. Treat them as the reason the shared code is exercised, not as
  something to review: a finding that one of them is wrong cannot be adjudicated here, because
  the sentence it would be wrong against is not in this tree. **The rule, so you can apply it
  yourself rather than trust the boundary: fixtures ship where the code they exercise ships.**
  It is what keeps `section-2.json` and what removed the other three files, and it is checked at
  release time against the crate directories rather than against any document that states it —
  so a future release cannot drop a fixture for code it still carries, which is the failure a
  reduction like this one invites.
  The siblings' presence is in scope in exactly one direction: whether they can affect this
  rung. A cross-rung announcement reaching this rung's scanner is specified behaviour, and
  §6 requires a `schemeId` mismatch be a **skip** rather than an error, because an error is a
  permanent scan abort any stranger can trigger for one announcement's gas.

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

  **What this tree does not let you check is the circumstance.** The blinded inputs, the
  implementer's transcript, and the comparison procedure are not here, and the ledger asserts
  the independence rather than evidencing it. So this is the strongest claim in this section
  and the one whose support is weakest in the artifact you are holding: you can check WHICH
  rows the repository says were witnessed, and you cannot check from here that they were
  witnessed blind. Treat it as a claim under this project's name, not as evidence you have
  verified — and if that distinction matters to your engagement, ask us for that material.
- **Measurement, with the harness committed.** Every gas figure comes from a real transaction
  against a real node, with its receipt in `harness/*/measured.json`;
  `tools/check_measured.py` re-derives the announcement figures from the EIP-7623 calldata rule
  without a node at all. A figure whose generator is absent would be unfalsifiable, which is
  worse than an absent figure.

**What none of that establishes.** The fixtures are generated by the Python in `tools/` and the
crates are tested against the fixtures, so "Rust agrees with Python" is internal consistency and
not correctness. The blinded re-derivation is what converts part of it into evidence, and it
covers the rows the record above names and no others.

## 6. Known limits of this tree in particular

- **No conformance runner ships.** The specification's Test Cases section requires that a third
  party be able to execute the fixtures against their own implementation without reading ours.
  This tree does not satisfy that requirement; the specification states it in place. What ships
  instead is the generator, which answers a different question — where the expected outputs came
  from, not whether somebody else's code reproduces them.
- **No pinned command output.** Nothing here records what a command printed, so a claim about
  behaviour has to be checked by running it.
- **The specification is a fold.** It is hand-authored from a common-definitions document and a
  per-payment document that specifies this rung as a delta against the KEM-only one, and its own
  header says so. Two documents specifying one wire format can diverge; a conservation gate in
  the authoring repository classifies every RFC 2119 occurrence in both and fails when one has
  no counterpart, but that gate proves correspondence, not agreement on meaning. **A divergence
  in substance is exactly the kind of finding worth filing.**

## 7. What is provisional, and why — read this before filing a finding about a constant

Some values here are decisions rather than derivations, and the specification marks them. A
constant marked provisional has no outside adopter: this tree's own implementation produces
those bytes and, where the record says so, a blinded re-derivation agreed on them, but nothing
external has committed to the value. **A finding that such a constant is wrong is welcome; a
finding that it is unsourced is already recorded.**

The domain separators, the 8-byte view tag width, the field order of the seed derivations and
the choice of ML-KEM-768 over other parameter sets are all in that class.

## 8. How to report

Say what an implementation would do wrong, and what a reader would take away that is not true.
A finding is strongest when it names the sentence, the bytes and the wrong behaviour it
produces; it is weakest when it names a preference. Where a fixture and the prose disagree, the
prose is the specification and the fixture is the defect — unless the prose is the ambiguous
one, which is item 5 of §2 and the most valuable thing you can bring back.
