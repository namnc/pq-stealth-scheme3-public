# PQ Stealth Addresses — schemeId 3

Post-quantum stealth addresses for Ethereum: one `schemeId` extending
[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) with an ML-KEM-768 encapsulation combined
with a secp256k1 ECDH secret (for implementation risk hedging), one announcement per payment, no protocol change.
**Spending stays ordinary secp256k1 ECDSA** - the announcement
layer is post-quantum, the spending is not.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B** |
| announcement, per payment | `epk` 33 B in `ephemeralPubKey`, `view_tag ‖ ct` 1 089 B in `metadata` = **1 122 B** |
| announcement gas, Prague | **69 360** upper bound; 69 300 for the one measured instance |
| first-time registration gas | **964 809** |
| a whole payment — announce, fund, spend | **111 300** |

Classical ERC-5564 announces 34 B for 28 067 gas and registers 66 B for
115 310. The registry entry is **18.9x the classical one in bytes** — 1 250 against 66 — and is
paid once per `schemeId`. The announcement is **2.47x in gas** — 69 360
against 28 067 — and is paid every time.

## What is here

| path | what it is |
|---|---|
| `spec/ERC-VVVV-schemeid3.md` | the specification and ERC *starter* |
| `crates/core` | the `StealthScheme` trait |
| `crates/ec` | secp256k1: SEC1 decoding, ECDH, scalar and point addition, the address |
| `crates/kem` | ML-KEM-768, over `ml-kem`, checked against NIST's own ACVP cases |
| `crates/per-payment` | the scheme itself |
| `vectors/` | the fixtures saying what each row pins and which wrong output it distinguishes |
| `harness/` | the gas harnesses: real transactions against a real node, with their receipts |
| `tools/` | the fixture generator, the size derivation and the gas verifier, each with its self-test |
| `contracts/` | the ERC-5564 announcer the gas harnesses measure against |

```bash
cargo test --workspace
```

```bash
python3 tools/gen_vectors.py --check
```

The fixtures are generated from `tools/vecprim.py`, which deliberately imports nothing from the reference
implementation that they test. For ML-KEM: the ciphertexts are of NIST's own ACVP file, vendored at
`vectors/tier1/`.

In `vectors/rederivation.json` 19 the 26 were re-derived by a second
implementer from the specification alone, and its `bytes_disagree` list
being empty *is* what we want.

```bash
python3 tools/check_measured.py
```

Re-derives every announcement figure from the EIP-7623 calldata rule and binds the rest to the
committed receipts, with no node needed.

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
