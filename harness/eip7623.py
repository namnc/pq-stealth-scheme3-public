"""EIP-7623 calldata accounting, shared by the gas benchmarks.

Every figure these benchmarks publish is a receipt. The one number that is NOT a
receipt is the all-nonzero upper bound, and it lives here because it is derived from
a receipt rather than measured beside it.

WHY IT IS DERIVED. A benchmark used to send a second transaction per row whose payload
carried no zero byte, so the published figure was a worst case for any key material. That
cost two transactions per row and a convention every document had to restate, and it bought
about 0.01% -- 60 gas on an announcement, 72 on a registration. It is also redundant:
byte VALUES reach the cost only through the token count, so flipping a payload's zero bytes
to nonzero is exactly `3` extra tokens each, and the receipt already reports how many zero
bytes the payload had. Measure the real sample, derive the bound.
"""

from __future__ import annotations

INTRINSIC = 21_000
TOKENS_PER_ZERO_BYTE = 1
TOKENS_PER_NONZERO_BYTE = 4
STANDARD_TOKEN_GAS = 4
FLOOR_TOKEN_GAS = 10


def tokens(observation: dict) -> int:
    """EIP-7623 token count over a transaction's whole calldata."""
    zero = observation["zero_bytes"]
    nonzero = observation["calldata_bytes"] - zero
    return TOKENS_PER_ZERO_BYTE * zero + TOKENS_PER_NONZERO_BYTE * nonzero


def floor_gas(token_count: int) -> int:
    """What the calldata floor alone charges for that many tokens."""
    return INTRINSIC + FLOOR_TOKEN_GAS * token_count


def floor_binds(observation: dict) -> bool:
    """Whether the receipt is the floor rather than the standard path.

    `gas_used` is `max(standard, floor)`, so the floor bound the transaction exactly when
    the receipt equals it. Execution is then not charged at all, which is why a floor-bound
    row cannot have its execution read off its own receipt.
    """
    return observation["gas_used"] == floor_gas(tokens(observation))


def all_nonzero_payload_bound(observation: dict, payload_zero_bytes: int) -> int:
    """Gas the SAME transaction would cost with no zero byte in its payload.

    Derived, not measured. Each payload zero byte becomes nonzero, which is
    `TOKENS_PER_NONZERO_BYTE - TOKENS_PER_ZERO_BYTE` more tokens, charged at the rate the
    row already pays. Execution is untouched: it is a function of calldata LENGTH, and the
    length does not move.

    The rate cannot change underneath this. A floor-bound row stays floor-bound, because
    tokens rise and the floor rises 10 per token while the standard path rises 4. A
    standard-path row could in principle cross to the floor, so that is asserted rather
    than assumed.
    """
    extra = (TOKENS_PER_NONZERO_BYTE - TOKENS_PER_ZERO_BYTE) * payload_zero_bytes
    on_floor = floor_binds(observation)
    rate = FLOOR_TOKEN_GAS if on_floor else STANDARD_TOKEN_GAS
    bound = observation["gas_used"] + rate * extra
    if not on_floor and floor_gas(tokens(observation) + extra) > bound:
        raise RuntimeError(
            "an all-nonzero payload would cross onto the EIP-7623 floor, so this bound "
            "cannot be derived at the standard rate"
        )
    return bound
