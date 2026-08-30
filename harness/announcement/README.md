# `announcement`

Standalone `announce()` transactions against the canonical ERC-5564 runtime.
Bytecode is committed as `deployed_bytecode.hex`, SHA-256 checked, installed at `0x55649E01B5Df198D18D95b5cc5051630cfD45564`, and read back before any send.

```bash
python3 harness/bench.py announcement --check
python3 harness/bench.py announcement --update
```

Each run boots a local Prague Anvil. `python3 harness/announcement/measure.py` accepts the same flags.

Cases:

- `classical_upper_bound`, `scheme3_upper_bound`: all-nonzero `ephemeralPubKey` and `metadata`, a fixed 20-byte stealth address, schemeId 1 vs schemeId 3 field lengths from `tools/derive_sizes.py`
- `scheme3_real_sample`: the shared Rust fixture

Each case also sends a same-length all-zero payload. The announcer ABI-decodes and logs, so execution follows calldata length.
Cheaper calldata tokens drop that send off the EIP-7623 floor.
The collector checks the primary receipt against `max(21000 + 4·tokens + execution, 21000 + 10·tokens)`.

Every send must emit one `Announcement` whose address, topics, and ABI data match the call.

Requires `anvil` and `cast`.
