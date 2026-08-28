# `announcement` — what one ERC-5564 announcement actually costs

Not a Foundry project. It drives `anvil` and `cast` directly, because **the thing being measured
cannot be observed from inside a Foundry test**:

<!-- gas-external: EIP-2929's COLD_ACCOUNT_ACCESS_COST, a protocol constant, not a receipt -->
* a test contract reaches the announcer with `CALL`, so it pays EIP-2929 cold account access
  (2 600) plus caller-side argument copy;
* a standalone announcement transaction executes no `CALL` at all, and EIP-2929 seeds
  `accessed_addresses` with `tx.to`, so it pays neither.

Measured in a test frame, the "execution" figure was about **2.1×** the real one. Because the
EIP-7623 floor binds on the post-quantum schemes — where execution is not charged at all — and
does **not** bind on the classical baseline, the whole of that error landed on the denominator
of every published ratio.

## Run it

```
python3 measure.py                # boots its own anvil, prints the table
python3 measure.py --json         # rewrites measured.json
python3 measure.py --rpc-url URL  # against an already-running node
```

Needs `anvil`, `cast` and `forge` on PATH. Exits 1 if any self-check fails.

## The field lengths are READ, not retyped

`CASES` is built from `tools/derive_sizes.py`, which re-derives every length from FIPS 203
rather than from any constant that produced it, and asserts them against §6.

## Two numbers, and how each is obtained

1. **`total`** — straight off the receipt. Ground truth, no arithmetic. It includes the 21 000
   intrinsic and every calldata byte, so no convention needs stating: it is the number a
   wallet's balance moves by.
2. **`execution`** — not directly observable when the floor binds, because the transaction then
   pays `21000 + 10·tokens` regardless of what the EVM did.

## What the self-check covers

* **every receipt re-derives from the EIP-7623 rule**: `max(21000 + 4·tokens + execution,
  21000 + 10·tokens)` must equal what the node reported;
* every measured payload length equals the length §6 specifies for that row, asserted against
  `derive_sizes.ANNOUNCE_ERC` rather than assumed from the import.

## `measured.json` is committed, and the guard checks it without a node

`tools/check_measured.py` re-derives every committed receipt from the EIP-7623 rule and from
§6's field lengths. No Foundry, no anvil, no network — run it after any wire change
(`python3 tools/check_measured.py`), and a figure that stopped matching its
payload fails, while the measurement itself stays a deliberate local act.
