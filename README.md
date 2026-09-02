# PQ Stealth Addresses — schemeId 3

Post-quantum stealth addresses for Ethereum: 
one `schemeId` extending [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) 
with an ML-KEM-768 encapsulation combined with a secp256k1 ECDH secret (for implementation risk hedging), 
one announcement per payment, no protocol change.
**Spending stays ordinary secp256k1 ECDSA** - 
hence, the announcement layer is post-quantum, the spending is NOT.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B** |
| announcement, per payment | `epk` 33 B in `ephemeralPubKey`, `view_tag ‖ ct` 1 089 B in `metadata` = **1 122 B** |
| announcement gas, Prague | **69 300** for the one measured instance |
| first-time registration gas | **964 737** for the measured instance |
| a whole payment (announce, fund, spend) | **111 300** |

The all-nonzero classical baselines are 28 313 gas for a 34 B announcement and 115 310 gas
for a 66 B registration. The registry entry is **18.9x the classical one in bytes** (1 250
against 66) and is paid once per `schemeId`. Against that classical baseline,
Scheme 3 is **2.45x in gas** (69 300 against 28 313) and is paid every time.

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
| `tools/` | fixture generation, size derivation, and offline snapshot/document checks |
| `contracts/` | a readable ERC-5564 announcer source counterpart; the harness pins deployed runtime bytes |

## Tests

Test with
```bash
cargo test --workspace
python3 tools/run_selftests.py
python3 tools/gen_vectors.py --check
```

`run_selftests.py` runs the three `tools/test-*.py` scripts (sizes, vector generator, snapshot and docs). `gen_vectors.py --check` regenerates `vectors/` and compares it to what is committed. `check_measured.py` is included in `run_selftests.py`.

Gas, against a local Anvil node:

```bash
python3 harness/bench.py all --check
```

The fixtures are generated from `tools/vecprim.py`, 
which is **independent** from the reference implementation that they test. 
spec_vector.rs (implementing the test vectors) in per_payment matches the two implementation outputs for additional correctness check.
For ML-KEM: the ciphertexts are of **NIST's own ACVP file**, vendored at `vectors/tier1/`.

## Kohaku Integration PoC

[Kohaku Plugin](https://github.com/0xakk0r0kamui/kohaku-sapq/tree/pqsa-scheme3/crates/pq-stealth-ts)

## Demo

[Code](https://github.com/0xakk0r0kamui/pq-stealth-scheme3-demo)
[Demo](https://0xakk0r0kamui.github.io/pq-stealth-scheme3-demo/)

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
