# `payment` — what a whole stealth payment costs, and whether the key works

**A payment is three transactions, and §6 measures one of them.**

```
1. announce(schemeId, stealthAddress, ephemeralPubKey, metadata)
2. a value transfer to stealthAddress
3. a spend FROM stealthAddress, signed with the derived key
```

`harness/announcement` measures (1) — the transaction whose size the whole ladder is an
argument about. It is not what a payment costs, which a reader of §6 could reasonably
assume; this harness exists to close that gap.

## Run it

```
# First, produce payment.json in this directory. From the repository root:
cargo run -q --example emit_payment_json -p pqsa-per-payment > harness/payment/payment.json

# then, from here:
python3 measure.py                # boots its own anvil, prints the table
python3 measure.py --json         # rewrites measured.json
python3 measure.py --rpc-url URL  # against an already-running node
```

Needs `anvil`, `cast`, `forge` and `cargo` on PATH.

## No derivations happen here

It consumes `payment.json` — addresses, payloads and derived keys —
produced by the reference implementation: here, by `crates/per-payment`'s
`emit_payment_json` example, which calls the library's own `keygen`, `announce`, `scan` and
`spend_key` and formats what comes back. It computes nothing itself. `measure.py` validates
the file before it spends anything.

## The `payment.json` contract

One object, one `cases` array, one entry per scheme to measure:

```json
{"cases": [{"scheme_id": 3,
            "stealth_address": "0x…20 bytes…",
            "spend_key":       "0x…32 bytes…",
            "epk_field":       "0x…the ephemeralPubKey bytes…",
            "metadata":        "0x…the metadata bytes…"}]}
```

`measure.py` checks shapes and lengths and then checks the pair: it funds
`stealth_address` and spends from it with `spend_key`, so a file whose key does not open its
address fails at the node rather than in a comparison here.

### The demonstration seed

```
keygen seed      seed[i] = (i * 7 + 3 + salt) mod 256,  salt = 0
                 128 bytes for schemeId 3                           (§2.1)
sender master    [0x5a; 32]
sender counter   0, the first draw
```

The private keys in `payment.json` are real private keys but it is acceptable in this
context: every value is meant to derive from a hard-coded demonstration seed,
the chain is a throwaway local anvil, and the addresses hold nothing but its play money.
