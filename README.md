# PQ Stealth Addresses — schemeId 3

Post-quantum stealth addresses for Ethereum: one `schemeId` extending
[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) with an ML-KEM-768 encapsulation combined
with a secp256k1 ECDH secret (for implementation risk hedging), one announcement per payment, no protocol change.

The view tag is **one byte**. ML-KEM rejects implicitly, so the KEM never tells a scanner
whether an announcement is its own — but the announcement carries the `stealthAddress`, and
§2.4 requires a scanner to compare the address it derives against it. That comparison is local
and exact, so the tag only has to be a prefilter and the remaining seven bytes buy nothing.

## The rung

A sender pays an address only the recipient can derive. The announcement is public and
permanent, so it is what an adversary records now and breaks later; this rung closes that
against a quantum adversary. **Spending stays ordinary secp256k1 ECDSA** - the announcement
layer is post-quantum, the spending is not.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B** |
| announcement, per payment | `epk` 33 B in `ephemeralPubKey`, `view_tag ‖ ct` 1 089 B in `metadata` = **1 122 B** |
| announcement gas, Prague | **69 360** upper bound; 69 300 for the one measured instance |
| first-time registration gas | **964 809** |
| a whole payment — announce, fund, spend | **111 300** |

For comparison, classical ERC-5564 announces 34 B for 28 067 gas and registers 66 B for
115 310. Gas is the one that matters for the announcement because it recurs, and bytes for the
registry entry because it is stored. The registry entry is **18.9x the classical one in bytes** — 1 250 against 66 — and is
paid once per `schemeId`, not once per payment. The announcement is **2.47x in gas** — 69 360
against 28 067 — and is paid every time.

## What is here

| path | what it is |
|---|---|
| `spec/ERC-VVVV-schemeid3.md` | the specification and ERC starter |
| `crates/core` | the `StealthScheme` trait |
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

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
