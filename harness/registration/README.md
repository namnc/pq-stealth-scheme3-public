# `registration` — the one-time ERC-6538 `registerKeys` call, priced

The cost a recipient pays **once per `schemeId`** to publish a meta-address, for every
row of §7's registration table.

**This harness prices every rung the project has, and a single-rung tree ships it whole.**
So it emits more rows than such a tree's §7 contains, and the extra ones price rungs whose
specification is not here. Slicing it would leave receipts that no longer match the figures
they vouch for, which is worse; what the extra rows are for is stated per row below. The announcement harness prices what a *sender* pays per
payment; this prices the other party's single lifetime transaction, whose cost is
dominated by **storage** rather than calldata — which is why it needed a run rather than
a derivation, and why what it runs against matters more than usual.

## What it runs against: the canonical deployment, not a recompilation

Registration cost depends on how the registry lays the value out, which the
specification does not specify and MUST NOT assume. So the measured object is the
**canonical ERC-6538 registry's deployed runtime bytecode** — read off Ethereum mainnet
at `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538` with `eth_getCode`, committed as
[`deployed_bytecode.hex`](deployed_bytecode.hex), SHA-256-pinned in `measure.py` and
checked at every run — installed into anvil with `anvil_setCode`. Compiling the
registry's source here would measure this machine's compiler settings; the deployed
artifact is what every wallet actually pays. A reader re-derives the file with one
`eth_getCode` against any mainnet node.

## Conventions, each stated because each moves the number

* **First registration, fresh registrant per row.** Every storage slot written goes
  zero → nonzero — the "registered once" cost. The three schemeId 6 categories share a
  `schemeId`, so one shared registrant would overwrite its own entry three times, a
  cheaper operation that is not the row's claim.
* **Nonzero payload of the exact derived length — a worst-case calldata convention,
  stated.** Lengths are read from `tools/derive_sizes.py` (re-derived from FIPS 203/204),
  not retyped. Byte values reach *storage* cost only through all-zero 32-byte slots, which
  real key material produces with probability ~2^-256 — but each zero byte in *calldata*
  is charged 12 gas less, and real key material has one in roughly 256 bytes. Each figure
  is therefore an upper bound that a real registration undercuts by a few hundred gas at
  the schemeId 6 sizes.
* **Prague hardfork, pinned.** Same reason as the announcement harness: anvil's default
  would silently reprice everything on a toolchain bump.

## Run

```bash
python3 harness/registration/measure.py           # boots its own anvil, prints the table
python3 harness/registration/measure.py --json    # rewrites measured.json
```

Requires `anvil` and `cast` (Foundry) on PATH. The self-check asserts every payload
length against the size model and that every figure is large enough to have actually
stored its slots (a first registration cannot cost less than 20 000 gas per fresh slot
touched); `--json` refuses to write receipts that fail it.

## What these figures may NOT do

They price one `registerKeys` call against the canonical registry. They MUST NOT be
read as a per-payment cost (registration is once per recipient per `schemeId`), and
they say nothing about re-registration, which overwrites nonzero slots and costs less.
