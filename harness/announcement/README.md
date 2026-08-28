# `announcement` — what one ERC-5564 announcement actually costs

**The harness lives beside the figures it generates, deliberately.** A number whose
generator lives in a tree the release cannot reference is unfalsifiable to the reader who
has only the release; the rule here is the number and its harness together, and they are.

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

`CASES` is built from `tools/derive_sizes.py`, which re-derives every length from FIPS 203 and
rather than from any constant that produced it, and asserts them against §6.

**The payload table is DERIVED from §6's wire model rather than hand-listed, and that
choice is load-bearing**: a hand-maintained list here can carry superseded scheme ids and a
superseded view-tag width while looking complete — a defect class this project has met
repeatedly — where a derived table moves the moment the wire model does.

Reading the lengths from the size harness means a wire change cannot leave the gas figures
measuring a payload the document no longer specifies — the failure mode this coupling
exists to prevent.

## Two numbers, and how each is obtained

1. **`total`** — straight off the receipt. Ground truth, no arithmetic. It includes the 21 000
   intrinsic and every calldata byte, so no convention needs stating: it is the number a
   wallet's balance moves by.
2. **`execution`** — not directly observable when the floor binds, because the transaction then
   pays `21000 + 10·tokens` regardless of what the EVM did.

   Recovered with a probe: the same call with an **all-zero** payload of the same length.
   Execution gas is a function of calldata *length* (LOG data is 8/byte regardless; memory
   expansion and `CALLDATACOPY` are length-driven) while the EIP-7623 token count is not — a
   zero byte is 1 token, a nonzero byte is 4. So the zero variant escapes the floor and exposes
   execution at identical execution cost.

   **That is an assumption, so it is validated rather than asserted.** On the schemes where the
   floor binds on neither variant, execution is recoverable from both and the two must agree
   exactly. The self-check fails if they do not.

## What the self-check covers

* the zero probe escapes the floor on every row — otherwise it teaches nothing;
* where execution is recoverable twice, the two agree exactly;
* **every receipt re-derives from the EIP-7623 rule**: `max(21000 + 4·tokens + execution,
  21000 + 10·tokens)` must equal what the node reported;
* every measured payload length equals the length §6 specifies for that row, asserted against
  `derive_sizes.ANNOUNCE_ERC` rather than assumed from the import.

## `measured.json` is committed, and the guard checks it without a node

`tools/check_measured.py` re-derives every committed receipt from the EIP-7623 rule and from
§6's field lengths. No Foundry, no anvil, no network — run it after any wire change
(`python3 tools/check_measured.py`), and a figure that stopped matching its
payload fails, while the measurement itself stays a deliberate local act.

That split is the point. Running the harness routinely would make the numbers a side effect
of a build; CHECKING them routinely makes a stale number a failure — the check costs
arithmetic, the measurement costs a node.
