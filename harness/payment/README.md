# `payment` — what a whole stealth payment costs, and whether the key works

**A payment is three transactions, and §7 measures one of them.**

```
1. announce(schemeId, stealthAddress, ephemeralPubKey, metadata)
2. a value transfer to stealthAddress
3. a spend FROM stealthAddress, signed with the derived key
```

`harness/announcement` measures (1) — the transaction whose size the whole ladder is an
argument about. It is not what a payment costs, which a reader of §7 could reasonably
assume; this harness exists to close that gap.

**(3) is the reason this exists.** Its gas is uninteresting; its *succeeding* is not. schemeIds 2
and 3 both claim the derived address is an ordinary EOA and the derived key an ordinary secp256k1
scalar, and this harness is what checks that against an EVM. `cast send --private-key <derived>`
either works or it does not, and the node decides, not us.

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

This harness does not implement the scheme and must not. A second implementation inside the
measuring tool is a second thing that can be wrong, and when the two disagree the measurement is
what a reader believes. It consumes `payment.json` — addresses, payloads and derived keys —
produced by the reference implementation: here, by `crates/per-payment`'s
`emit_payment_json` example, which calls the library's own `keygen`, `announce`, `scan` and
`spend_key` and formats what comes back. It computes nothing itself. `measure.py` validates
the file before it spends anything.

## The `payment.json` contract

One object, one `cases` array, one entry per rung to measure:

```json
{"cases": [{"scheme_id": 3,
            "stealth_address": "0x…20 bytes…",
            "spend_key":       "0x…32 bytes…",
            "epk_field":       "0x…the ephemeralPubKey bytes…",
            "metadata":        "0x…the metadata bytes…"}]}
```

`stealth_address` is the address §2.4 derives, `spend_key` the scalar §2.6 derives for it, and
`epk_field` and `metadata` the two ERC-5564 payloads exactly as §6's wire table gives them for
that `schemeId`. `measure.py` checks shapes and lengths and then checks the pair: it funds
`stealth_address` and spends from it with `spend_key`, so a file whose key does not open its
address fails at the node rather than in a comparison here.

### The demonstration seed, stated rather than named

`measured.json` labels its input `the demonstration seed, salt 0`, and a label is not a seed. The
committed receipts are falsifiable only if a second party can produce the same input, so here is
all of it — three constants and one counter, with no file to obtain:

```
keygen seed      seed[i] = (i * 7 + 3 + salt) mod 256,  salt = 0
                 96 bytes for schemeId 2, 128 bytes for schemeId 3   (§2.1, and §2.9's delta)
sender master    [0x5a; 32]
sender counter   0, the first draw
```

Feed the keygen seed to `keygen`, resume a sender at that master and counter, draw one announce
seed, and announce. That reproduces the exact `epk_field` and `metadata` behind the committed
`69 510` and `111 510`, which matters more than it looks: under EIP-7623 the figure depends on
the ciphertext's ZERO-BYTE COUNT, so a different seed gives a different number and a reader
comparing against one would conclude the receipt was wrong. A tree carrying the demonstration
crate does all of this with `--emit-payment-json`; a tree carrying only the per-payment library
does it in about fifteen lines against that library's own API.

## About the private keys in `payment.json`

They are real private keys and they are printed in a file. That is acceptable in exactly this
context and nowhere else: every value is meant to derive from a hard-coded demonstration seed,
the chain is a throwaway local anvil, and the addresses hold nothing but its play money.

**What ENFORCES that here is that the emitter takes no input.** The demonstration seed is
written into `emit_payment_json.rs` as the three constants below and there is no flag, no path
and no environment variable that could point it at anything else — so the file cannot be
produced from real key material without editing the source, which is a different act from
running a command. A tree whose emitter accepts a seed has a rule you keep rather than a check
that has already run; this one does not.

`payment.json` is regenerated rather than committed, which is why the release does not contain it and why the command above is the first step rather than a note.

## What this does not establish

A local node is not mainnet, and gas is not price. (2) and (3) are also the least interesting
transactions in the sequence — a transfer to a cold account and an ordinary send. Their value is as
a **denominator**: they are what the announcement should be compared against when someone asks
whether a post-quantum stealth payment is expensive.
