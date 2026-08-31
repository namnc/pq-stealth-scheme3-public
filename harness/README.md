# Gas benchmarks

From Rust Scheme 3 fixture, using a fresh Prague Anvil, pinned ERC-5564 and ERC-6538 runtime bytecode, creating real transactions, then reading receipt `gasUsed`.

- `announcement`: standalone ERC-5564 `announce()` calls
- `registration`: first `registerKeys` on the canonical ERC-6538 registry
- `payment`: announce, fund the stealth address, spend with the derived key

From the repository root:

```bash
python3 harness/bench.py all --check
python3 harness/bench.py all --update
```

`--check` reruns every transaction and requires `measured.json` to match.
`--update` rewrites those files. 
Pass `announcement`, `registration`, or `payment` instead of `all` for one benchmark.

`measured.json` stores hardfork, contract identity, fixture identity, calldata length, zero-byte count, and `gasUsed`.
Each row also carries `payload_zero_bytes` and `upper_bound_gas` -- what the same transaction would cost with no zero byte in its payload.
That one is DERIVED from the row beside it by `harness/eip7623.py`, not measured, and it is the only published number that is not a receipt.

