# `registration`

First-time `registerKeys(uint256,bytes)` against the canonical ERC-6538 registry at `0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538`.
Runtime bytecode is committed as `deployed_bytecode.hex`, SHA-256 checked, installed on a fresh Prague Anvil, and read back.

```bash
python3 harness/bench.py registration --check
python3 harness/bench.py registration --update
```

`python3 harness/registration/measure.py` accepts the same flags.

Each case uses a different funded caller. Upper-bound cases use all-nonzero meta-address bytes. `scheme3_real_sample` registers the shared Rust meta-address.

`stealthMetaAddressOf(caller, schemeId)` is empty before the transaction and equals the submitted bytes after.

Field lengths come from `tools/derive_sizes.py`. Calldata length is checked against the ABI encoding.

Requires `anvil` and `cast`.
