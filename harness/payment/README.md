# `payment`

Three native-ETH transactions on a fresh Prague Anvil:

1. `announce` through the canonical ERC-5564 runtime
2. fund the derived stealth address
3. spend from that address with the derived key

```bash
python3 harness/bench.py payment --check
python3 harness/bench.py payment --update
```

`python3 harness/payment/measure.py` accepts the same flags.

The harness runs `crates/per-payment/examples/emit_payment_json.rs` (`keygen`, `announce`, `scan`, `spend_key`).
The canonicalized JSON is SHA-256'd into the artifact.

Before value moves, the spend key must derive the stealth address and both endpoints must be EOAs.
After each send the collector checks the announcement event, receipt `from`/`to`, the funded amount, the spent amount, and the stealth balance after value and fee.

`measured.json` stores the three `gasUsed` values. The printed total is their sum.

Requires `cargo`, `anvil`, and `cast`.
