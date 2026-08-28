# `registration` — the one-time ERC-6538 `registerKeys` call, priced

The cost a recipient pays **once per `schemeId`** to publish a meta-address, for every
row of §6's registration table.

## What it runs against: the canonical deployment, not a recompilation

For precision, the measured object is the
**canonical ERC-6538 registry's deployed runtime bytecode** — read off Ethereum mainnet
at `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538` with `eth_getCode`, committed as
[`deployed_bytecode.hex`](deployed_bytecode.hex), SHA-256-pinned in `measure.py` and
checked at every run — installed into anvil with `anvil_setCode`.

## Conventions, each stated because each moves the number

* **First registration, fresh registrant per row.** Every storage slot written goes
  zero -> nonzero -- the "registered once" cost.
* **Nonzero payload of the exact derived length — a worst-case calldata convention,
  stated.** Lengths are read from `tools/derive_sizes.py` (re-derived from FIPS 203/204),
  not retyped. Byte values reach *storage* cost only through an all-zero 32-byte slot,
  which real key material gives with probability 2^-256 per full slot — but each zero byte
  in *calldata* is charged 12 gas less on the standard EIP-7623 path these rows take, and
  real key material has one zero byte in roughly 256. Each figure is therefore an upper
  bound, and by an amount that is arithmetic rather than a guess: **about 59 gas** at
  schemeId 3's 1 250 bytes. `tools/derive_sizes.py` derives it per row, so it is a figure
  with a generator rather than a figure in a sentence.
* **Prague hardfork, pinned.** Same reason as the announcement harness: anvil's default
  would silently reprice everything on a toolchain bump.

## Run

```bash
python3 harness/registration/measure.py           # boots its own anvil, prints the table
python3 harness/registration/measure.py --json    # rewrites measured.json
```

<!-- gas-external: 20 000 is EIP-2200's SSTORE_SET_GAS, a protocol constant, not a receipt -->
Requires `anvil` and `cast` (Foundry) on PATH. The self-check asserts every payload
length against the size model and that every figure is large enough to have actually
stored its slots (a first registration cannot cost less than 20 000 gas per fresh slot
touched); `--json` refuses to write receipts that fail it.

## What these figures may NOT do

They price one `registerKeys` call against the canonical registry. They MUST NOT be
read as a per-payment cost (registration is once per recipient per `schemeId`), and
they say nothing about re-registration, which overwrites nonzero slots and costs less.
