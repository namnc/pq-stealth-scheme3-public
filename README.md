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
| announcement, per payment | `epk ‖ ct` 1 121 B in `ephemeralPubKey`, `view_tag` 1 B in `metadata` = **1 122 B** |
| announcement gas, Prague | **69 330** for the one measured instance |
| first-time registration gas | **964 737** for the measured instance |
| a whole payment (announce, fund, spend) | **111 330** |

The all-nonzero classical baselines are 28 313 gas for a 34 B announcement and 115 310 gas
for a 66 B registration. The registry entry is **18.9x the classical one in bytes** (1 250
against 66) and is paid once per `schemeId`. Against that classical baseline,
Scheme 3 is **2.45x in gas** (69 330 against 28 313) and is paid every time.

See further on [ethresearch](https://ethresear.ch/t/pq-anonymity-for-stealth-address-protocol/26094).
The specification is [ERC-8441](https://github.com/ethereum/ERCs/pull/2059), in draft, and is discussed on
[Ethereum Magicians](https://ethereum-magicians.org/t/erc-8441-hybrid-post-quantum-stealth-address-scheme/29923).

## What is here

| path | what it is |
|---|---|
| `spec/ERC-8441-schemeid3.md` | the specification, a copy of `ERCS/erc-8441.md` in ethereum/ERCs, where its links resolve |
| `crates/core` | the `StealthScheme` trait |
| `crates/ec` | secp256k1: SEC1 decoding, ECDH, scalar and point addition, the address |
| `crates/kem` | the `Kem` trait; ML-KEM-768, over `ml-kem`, checked against NIST's own ACVP cases; `Pair`, two KEMs side by side |
| `crates/per-payment` | the construction, generic over a KEM `Suite`; `SchemeId3` is its ML-KEM-768 suite; ERC-5564's three methods for it (`erc5564`) |
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

## Secret ownership

Owned seeds, shared secrets and offsets use `zeroize::Zeroizing`; spending keys use
`secrecy::SecretBox<[u8; 32]>`. Borrow signer input with `SchemeId3::spend_key_bytes(&key)`
via the `ExportableSpendKey` trait. Borrowed inputs and copies made by callers/signers need
their own secret owners. `Zeroizing` does not redact direct field debug output; the aggregate
secret types and spending key do redact it.

## Public representations

Construct `MetaAddress` and `Announcement` with `new(...)` or the byte parsers. Their
viewing/ephemeral points are required `CompressedPoint` values; private `ek`/`ct` buffers
have checked lengths and read-only `ek()`/`ct()` getters. Constructors check wire shape;
ML-KEM key validation and implicit rejection remain in the KEM engine.

## Other KEM suites

`schemeId` 3 is one suite of the construction: the spec's Section 4 says what another ERC fixes
to reuse it with a different KEM under its own `schemeId`, and Section 2.3 how senders choose
between the suites a recipient registered. In code a suite is four items:

```rust
#[derive(Clone, Copy, Debug)]
struct MySuite;

impl pqsa_per_payment::Suite for MySuite {
    const SCHEME_ID: u64 = /* its own schemeId */ 0xffff_0001;
    const NAME: &'static str = "my suite";
    const DOMAIN_SEPARATOR: &'static [u8] = b"my-suite/hybrid-payment/v1";
    type Kem = pqsa_kem::Pair<pqsa_kem::MlKem768, OtherKem>;
}

type MyScheme = pqsa_per_payment::Hybrid<MySuite>;
```

`MyScheme` then has the whole `StealthScheme` interface, with its lengths taken from the KEM.
`crates/per-payment/tests/second_suite.rs` defines two such suites and checks that they round-trip
payments and that schemeId 3 and they skip each other's announcements. `SchemeId3`, `MetaAddress`,
`Announcement` and `Scanner` are the ML-KEM-768 suite's, as before; the scanner now keeps the
expanded decapsulation key from `bind` instead of rebuilding it for every announcement.

## Randomness and key seeds

`announce_random` is the sender: it draws `esk` and ML-KEM's `m` from the operating system's
CSPRNG, as the spec's Section 2.4 requires. The seeded `announce` takes that randomness as input
so the vectors, the demo and the gas harness are reproducible; it is not a sender for real
payments. The harness feeds it seeds from SHAKE256 over a fixed secret and a counter, and takes
its keys from a fixed 128-byte keygen seed.

`keygen_seed` in `crates/core` derives a keygen seed from a 32-byte master key with HKDF-SHA256.
It is one way to meet the spec's Section 2.1, not part of the standard.

## Kohaku Integration PoC

[Kohaku-ts Plugin](https://github.com/0xakk0r0kamui/kohaku-sapq/tree/pqsa-scheme3/crates/pq-stealth-ts)

[Kohaku-rs Plugin](https://github.com/0xakk0r0kamui/kohaku-sapq-rs/tree/feat/kohaku-stealth/crates/stealth)

## Demo

[Code](https://github.com/0xakk0r0kamui/pq-stealth-scheme3-demo)

[Demo](https://0xakk0r0kamui.github.io/pq-stealth-scheme3-demo/)

[CLI](https://github.com/0xakk0r0kamui/pq-stealth-scheme3-demo-cli)

The TypeScript plugin and the demo predate the current wire layout. They put `ct` in `metadata`,
so their announcements do not interoperate with this tree's until they move `ct` into
`ephemeralPubKey`.

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
