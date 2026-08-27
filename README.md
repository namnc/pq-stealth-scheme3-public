# PQ Stealth Addresses — schemeId 3

Post-quantum stealth addresses for Ethereum: one `schemeId` extending
[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) with an ML-KEM-768 encapsulation combined
with a secp256k1 ECDH secret, one announcement per payment, no protocol change and no
per-counterparty state on either side.

**Status: starter draft. Not submitted, not normative, not externally reviewed, and no
`schemeId` is reserved.** Every figure below is measured or re-derivable from something in this
tree.

**If you are here to review it, start with [`AUDIT.md`](AUDIT.md)** — it says what is being
asked, what evidence already exists and of what kind, and at length what is not covered.

## The rung

A sender pays an address only the recipient can derive. The announcement is public and
permanent, so it is what an adversary records now and breaks later; this rung closes that
against a quantum adversary. **Spending stays ordinary secp256k1 ECDSA** — the announcement
layer is post-quantum, the money is not.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B** |
| announcement, per payment | `epk` 33 B in `ephemeralPubKey`, `view_tag ‖ ct` 1 096 B in `metadata` = **1 129 B** |
| announcement gas, Prague | **69 570** upper bound; 69 510 for the one measured instance |
| first-time registration gas | **964 809** |
| a whole payment — announce, fund, spend | **111 510** |

For comparison, classical ERC-5564 announces 34 B for 28 067 gas and registers 66 B for
115 310. The registry entry is **18.9× the classical one in bytes** — 1 250 against 66 — and is
paid once per `schemeId`, not once per payment. The announcement is **2.48× in gas** — 69 570
against 28 067 — and is paid every time. **The two multiples are not on the same basis**, which
is why each says which it is: in gas the registry entry is 8.4×, and in bytes the announcement
is 33.2×. Gas is the one that matters for the announcement because it recurs, and bytes for the
registry entry because it is stored.

**Hybrid.** `ss` is SHA3-256 of the ECDH secret, the ML-KEM secret, and the public fields
`epk`, `ct`, `viewing_pk_ec`, `ek`. Both secrets are inputs. Spending is secp256k1 ECDSA.
The hash does not change `ct` or `ek`; those stay public (log and registry). Cost: 33 bytes
on the registry entry and about 2.4% of announcement gas versus the KEM-only variant; the
two are different `schemeId`s because their meta-address lengths differ.

## What is here

| path | what it is |
|---|---|
| `spec/ERC-VVVV-schemeid3.md` | the specification — one document, one scheme, nothing to cross-reference |
| `crates/core` | the `StealthScheme` trait, §1's offset and view tag, §5's seed derivations, the delegation guard |
| `crates/ec` | secp256k1: SEC1 decoding, ECDH, scalar and point addition, the address |
| `crates/kem` | ML-KEM-768, over `ml-kem`, checked against NIST's own ACVP cases |
| `crates/per-payment` | the rung itself |
| `vectors/` | the fixtures, with `PLAN.md` saying what each row pins and which wrong output it distinguishes |
| `harness/` | the gas harnesses: real transactions against a real node, with their receipts |
| `tools/` | the fixture generator, the size derivation and the gas verifier, each with its self-test |
| `contracts/` | the ERC-5564 announcer the gas harnesses measure against |

```bash
cargo test --workspace
```

```bash
pip install --no-deps kyber-py==1.2.0     # an ML-KEM independent of the Rust one
python3 tools/gen_vectors.py --check --wave 1
```

The fixtures are generated from `tools/vecprim.py`, which imports nothing from the reference
implementation — so what the crates are tested against does not come from the crates. Without
`kyber-py` the check still runs and reports the rows it could not rebuild rather than passing
over them.

```bash
python3 tools/check_measured.py
```

Re-derives every announcement figure from the EIP-7623 calldata rule and binds the rest to the
committed receipts, with no node needed — so a figure that stops matching fails rather than
persisting.

**`--wave 1` is the whole of `vectors/` here**, not a part of it. The generator groups the
ladder's fixtures into waves and takes one per invocation; the rungs in the other two waves are
the ones whose files this tree does not carry, so that single command regenerates and compares
every fixture row present.

## What is not here, and it matters

- **No conformance runner.** The specification's Test Cases section requires that a third party
  be able to run the fixtures against their own implementation without reading ours. **This tree
  does not satisfy that**, the specification says so in place, and what ships instead is the
  generator: the fixtures are plain JSON and their provenance is independent of the code they
  check.
- **No sibling specifications, and almost no sibling fixtures.** The ladder this rung belongs to has others: a KEM-only per-payment
  variant, a pairwise-channel pair, and a post-quantum *spending* rung. **None of their
  specifications ship**, which is the point of this tree. The channel pair's and the spending
  rung's fixtures do not ship either, and `vectors/` describes only what is in it — the plan,
  the manifest and the re-derivation ledger were each cut to the four files that remain, and
  the release build re-derives all three and refuses to publish a tree where any of them has
  drifted. That check alone would not be worth much, since all three are cut by the same
  decision and would agree with each other about a wrong set. What makes it load-bearing is a
  separate one that reconciles the fixtures against the **crate directories** instead: a rung
  whose crate ships without its fixtures fails the build, and so does a fixture whose crate is
  absent. The rule below is enforced rather than asserted, and the thing enforcing it does not
  read the documents that state it.
  Two things of the KEM-only variant's are still here, for one reason. Its **code** ships
  inside `crates/per-payment`, because §2.8 requires the code from the shared secret onward be
  shared rather than duplicated: a crate carrying only this rung would violate the document it
  implements. Its **fixtures** ship because that code would otherwise be untested — the rule
  applied here is that fixtures ship where the code they exercise ships, and it is the same
  rule that removed the other three files, whose rungs have no implementation in this tree.
  So `vectors/section-2.json` pins a rung whose text you do not have. `AUDIT.md` says what
  that means for an engagement.
- **No pinned command output.** Commands above are runnable; nothing here records what they
  printed, so run them.
- **Nothing is deployed.** No contract of ours is on any network, no `schemeId` is reserved, and
  the gas figures cover the transactions named above and nothing else.

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
