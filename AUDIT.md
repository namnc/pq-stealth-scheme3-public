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
4. **The fixtures that have a specification here** — `vectors/section-2_9.json` (this rung) and
   the shared `vectors/section-1.json` and `vectors/section-5.json` — and whether each pins the
   normative sentence it claims to. **The other four files are not in scope and §3 says why**:
   they belong to rungs whose text is absent, so there is no sentence in this tree for a row of
   theirs to be wrong against. That is 51 of the 75 rows; budget the engagement for 24.
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
- **The sibling rungs — whose code and fixtures you are nonetheless holding.** The KEM-only
  per-payment variant's code ships inside `crates/per-payment` — §2.8 requires the code from
  the shared secret onward be shared rather than duplicated — but its specification does not
  ship and its behaviour is not what this engagement is about.
  The same is true of the fixtures, and there it is the larger share: **51 of the 75 rows in
  `vectors/` pin rungs whose text is absent** — `section-2.json`, `section-3.json`,
  `section-3_12.json` and `section-4.json` are wholly theirs, and `vectors/PLAN.md` covers the
  ladder rather than this rung. Only `section-2_9.json` (this rung) and the shared
  `section-1.json` and `section-5.json` are reviewable against a document you have. **Do not
  spend the engagement on the other four.** They are here because the generator emits the set
  as a set and `--check` compares the whole of it; a finding that one of their rows is wrong
  cannot be adjudicated in this tree, since the sentence it would be wrong against is not in it.
  The siblings' presence is in scope in exactly one direction: whether they can affect this
  rung. A cross-rung announcement reaching this rung's scanner is specified behaviour, and
  §6 requires a `schemeId` mismatch be a **skip** rather than an error, because an error is a
  permanent scan abort any stranger can trigger for one announcement's gas.

## 4. Threat model, in one paragraph

The adversary records every announcement and every registry entry today, and acquires a
cryptographically relevant quantum computer later. Against that adversary the question is
whether an announcement can be linked to the recipient who could spend it. The adversary is not
assumed to control the recipient's device, to see the sender's entropy source, or to break
ML-KEM-768 and secp256k1 ECDH at once — the hybrid exists precisely so that one of the two
failing is survivable. Denial of service against a scanner is in scope where the specification
makes a claim about it, which is why the `schemeId`-mismatch rule above is normative.

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
  library. **Read its keys rather than this description of them**, because there are five and a
  summary is where a category goes missing. `bytes_agree` and `outcome_only` are the two kinds
  of agreement; `bytes_disagree` is empty and its being empty is the claim that none disagreed;
  `ungeneratable` names a row the re-derivation could not compute, which is a fact about the
  second implementer's sandbox rather than about the row; and `absent` names a row it did not
  attempt at all. The last two are different and the file keeps them apart: an `ungeneratable`
  row was reached and not computed, an `absent` row was never reached. **`absent` is authoritative
  when populated** — it is empty in the tree you are holding, so every row here sits in one of
  the other four, but do not reconstruct it by subtraction. Those lists cut across the specification's
  sections and coincide with no section's row list, so read the file rather than any total quoted
  about it — including one quoted here, which is why none is.

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
