# `registration` — the one-time ERC-6538 `registerKeys` call, priced

For precision, the measured object is the
**canonical ERC-6538 registry's deployed runtime bytecode** — read off Ethereum mainnet
at `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538` with `eth_getCode`, committed as
[`deployed_bytecode.hex`](deployed_bytecode.hex), SHA-256-pinned in `measure.py` and
checked at every run — installed into anvil with `anvil_setCode`.

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
