# Gas benchmarks

A Rust Scheme 3 fixture, a fresh Prague Anvil, pinned ERC-5564 and ERC-6538 runtime bytecode, real transactions, then receipt `gasUsed`.

- `announcement`: standalone ERC-5564 `announce()` calls
- `registration`: first `registerKeys` on the canonical ERC-6538 registry
- `payment`: announce, fund the stealth address, spend with the derived key

From the repository root:

```bash
python3 harness/bench.py all --check
python3 harness/bench.py all --update
```

`--check` reruns every transaction and requires `measured.json` to match.
`--update` rewrites those files. Pass `announcement`, `registration`, or
`payment` instead of `all` for one benchmark. `python3 harness/<name>/measure.py` is the same single-benchmark entry.

All three consume one deterministic fixture from `crates/per-payment`.
`real_sample` rows are that fixture. Upper-bound rows fill dynamic ABI fields with all-nonzero bytes. Announcement also records same-shape all-zero sends under `diagnostics`, used to recover execution under EIP-7623.

`measured.json` stores hardfork, contract identity, fixture identity, calldata length, zero-byte count, and `gasUsed`. Printed totals and EIP-7623 labels are computed at display time.

Interpreted tables live in spec §6. `python3 tools/check_measured.py` checks snapshot identity and that gas figures in prose appear in the snapshots.
