"""Primitives for the conformance-vector generator, and **nothing from this repository**.

`tools/gen_vectors.py` may not import the code it validates -- a fixture derived from that code
tests self-consistency and nothing else, which is why the generator comes ahead of any
cryptography. This module is the other half of that rule: the arithmetic
the generator needs, written from the standards rather than taken from `crates/`.

WHY IT IS WRITTEN HERE RATHER THAN INSTALLED. Checked against a stock CPython: `hashlib` has
SHAKE256 and SHA3-256, and **it does not have keccak256** -- `keccak_256` is absent from
`hashlib.algorithms_available`, and SHA3-256 is a different function, while §2.9's address
derivation needs keccak. There is no `coincurve`, no `ecdsa`, no `secp256k1`. Adding a
dependency would trade the standalone property for convenience, and both of these are small
enough to write and check against published answers.

WHAT IT IS NOT. **Not constant-time, and it must never be described as such.** This generates
fixtures; it runs on the author's machine against values that are already published in the
files it writes. A timing side channel here leaks nothing. `crates/pqsa-ec` is where the
constant-time requirement lives, and copying this arithmetic into it would be a defect.

Not a KEM either. ML-KEM-768 in pure Python is a project rather than a function, and writing
one would put a second unreviewed KEM in the tree -- so the generator consumes NIST ACVP
`(ek, m, ct, ss)` tuples instead, which is what the tier-1/tier-2 split already says: tier 1
is ACVP and "we generate nothing".

Every function below is checked by `tools/test-gen-vectors.py` against a value published
somewhere other than this repository.
"""

from __future__ import annotations

import hashlib
import os

# --------------------------------------------------------------------------------------
# keccak256, from FIPS 202's permutation with the ORIGINAL Keccak padding
# --------------------------------------------------------------------------------------
#
# The difference between this and SHA3-256 is one byte: SHA3 appends the domain separator
# `0x06` and Keccak appends `0x01`. Nothing else. That single byte is why substituting
# `hashlib.sha3_256` for keccak256 produces a plausible-looking address that no Ethereum node
# agrees with, and it is the reason this is written out rather than approximated.

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)
_MASK = (1 << 64) - 1


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _MASK


def _keccak_f1600(a: list[list[int]]) -> None:
    for rnd in range(24):
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # rho and pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _MASK) & b[(x + 2) % 5][y])
        # iota
        a[0][0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Original-Keccak 256, as Ethereum uses it. **Not SHA3-256** -- see this module's note."""
    rate = 136  # 1088 bits, for a 256-bit digest
    padded = bytearray(data)
    padded.append(0x01)  # Keccak's domain byte. SHA3-256 would append 0x06.
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    for i in range(4):  # 4 lanes = 32 bytes
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


# --------------------------------------------------------------------------------------
# secp256k1, from SEC 2 §2.4.1
# --------------------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

Point = tuple[int, int] | None


def is_on_curve(pt: Point) -> bool:
    if pt is None:
        return True
    x, y = pt
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - x * x * x - 7) % P == 0


def add(a: Point, b: Point) -> Point:
    """Affine addition. Slow and clear; correctness is the only requirement here."""
    if a is None:
        return b
    if b is None:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx and (ay + by) % P == 0:
        return None
    if a == b:
        lam = (3 * ax * ax) * pow(2 * ay, P - 2, P) % P
    else:
        lam = (by - ay) * pow(bx - ax, P - 2, P) % P
    x = (lam * lam - ax - bx) % P
    y = (lam * (ax - x) - ay) % P
    return (x, y)


def mul(k: int, pt: Point = G) -> Point:
    """Scalar multiplication. **Not constant-time**, deliberately -- see the module note."""
    if k % N == 0 or pt is None:
        return None
    acc: Point = None
    addend = pt
    k %= N
    while k:
        if k & 1:
            acc = add(acc, addend)
        addend = add(addend, addend)
        k >>= 1
    return acc


def encode_compressed(pt: Point) -> bytes:
    """SEC1 compressed: 33 bytes, tag `0x02` for even y and `0x03` for odd."""
    if pt is None:
        raise ValueError("the point at infinity has no SEC1 encoding")
    x, y = pt
    return bytes([0x02 + (y & 1)]) + x.to_bytes(32, "big")


def encode_uncompressed(pt: Point) -> bytes:
    """SEC1 uncompressed: 65 bytes, `0x04 ‖ x ‖ y`. The address derivation drops the tag."""
    if pt is None:
        raise ValueError("the point at infinity has no SEC1 encoding")
    x, y = pt
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def decode_compressed(b: bytes) -> Point:
    """Decode, accepting **only** `0x02` and `0x03`.

    Rejects the SEC1 **compact** `0x05` form, which §2.2 turns on: at least one widely used
    stack canonicalises it to the same point as the compressed encodings, so accepting it gives
    one key two on-chain encodings and therefore two meta-addresses. Raises `ValueError` for
    every rejection, without distinguishing which check failed -- §2.2 asks for rejection, not
    diagnosis.
    """
    if len(b) != 33 or b[0] not in (0x02, 0x03):
        raise ValueError("not a SEC1 compressed point")
    x = int.from_bytes(b[1:], "big")
    if x >= P:
        raise ValueError("x is at or above the field modulus")
    y2 = (x * x * x + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y * y - y2) % P != 0:
        raise ValueError("x is not on the curve")
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


def address_of(pt: Point) -> bytes:
    """The Ethereum address: `keccak256(uncompressed(pk)[1..])[12..32]`.

    The `[1..]` drops the `0x04` tag, and V2-09's `wrong` column names including it as the
    likely error. `[12..32]` and not `[0..20]` -- the other named error.
    """
    return keccak256(encode_uncompressed(pt)[1:])[12:]


def eip55(addr20: bytes) -> str:
    """The EIP-55 mixed-case checksum form, which V2-09 asks for alongside the raw bytes."""
    low = addr20.hex()
    h = keccak256(low.encode()).hex()
    return "0x" + "".join(
        c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c for i, c in enumerate(low)
    )


# --------------------------------------------------------------------------------------
# The derivations of §1 and §5, from the specification text
# --------------------------------------------------------------------------------------

DS_OFFSET = b"pq-stealth/offset/v1"
DS_VIEWTAG = b"pq-stealth/view-tag/v1"

# §5's canonical KEM name for the deployed path. `kem_id` wraps it with its length.
KEM_NAME = b"ML-KEM-768"


# --------------------------------------------------------------------------------------
# ML-KEM-768, from a third-party implementation, OPTIONAL
# --------------------------------------------------------------------------------------
#
# `kyber-py` if it is installed, `None` otherwise. Optional on purpose: this repository
# otherwise has no external dependency at all, and a generator that cannot run from a bare
# checkout is one a reviewer cannot run either -- and a check nobody can run is a check
# that reports nothing. Rows needing a KEM are
# emitted when it is present and RECORDED AS ABSENT WITH THE REASON when it is not, so the
# plan-coverage invariant holds either way.
#
# WHY A THIRD-PARTY IMPLEMENTATION IS THE RIGHT ORACLE and not a convenience:
#
#   * the standalone rule forbids importing the code the vectors validate -- OURS. A Python
#     implementation is necessarily a different implementation from the Rust we ship, which is
#     the property the rule is actually about.
#   * the trust question has an ANSWER rather than an assurance. It is not trusted because it
#     is popular; it is trusted for exactly the tuples it reproduces from NIST's ACVP file,
#     and `acvp_selftest()` below is that check, run every time the generator runs.
# `PQSA_NO_KEM=1` forces the absent branch. A TEST SEAM, and it exists because the suite has
# to cover BOTH worlds on one machine: with the library, the KEM-bearing rows are emitted and
# carry round-trip evidence; without it, they are recorded as absent with the reason. A suite
# that could only test whichever world the runner happened to be in would have one branch
# permanently unexercised -- and the absent branch is the one a bare checkout takes, so it is
# the one a reviewer sees first.
if os.environ.get("PQSA_NO_KEM") == "1":                    # pragma: no cover - env dependent
    _ML_KEM_768 = None
else:
    try:                                                    # pragma: no cover - env dependent
        from kyber_py.ml_kem import ML_KEM_768 as _ML_KEM_768
    except ImportError:                                     # pragma: no cover
        _ML_KEM_768 = None

KEM_ABSENT = ("kyber-py is not installed, so rows needing an ML-KEM round trip cannot be "
              "built. Install it and re-run; the row is recorded rather than synthesised "
              "because a fabricated ct or ss in a conformance fixture would pass.")


def have_kem() -> bool:
    """Whether an ML-KEM implementation is available to this process."""
    return _ML_KEM_768 is not None


def kem_keygen(dz: bytes) -> tuple[bytes, bytes]:
    """`ML-KEM.KeyGen_internal(d, z)` -> `(ek, dk)`. §1 requires the internal entry point.

    Takes the 64-byte `(d, z)` seed because §1 requires the decapsulation key to be
    represented as that seed rather than the expanded form -- so the caller holds 64 bytes and
    expands on demand, which is the property that makes the tracking key 64 bytes and not
    2 400.
    """
    assert len(dz) == 64, f"(d, z) is 64 bytes, got {len(dz)}"
    return _ML_KEM_768._keygen_internal(dz[:32], dz[32:])


def kem_encaps(ek: bytes, m: bytes) -> tuple[bytes, bytes]:
    """`ML-KEM.Encaps_internal(ek, m)` -> `(ct, ss)`. Deterministic in `m`, per §2.3.

    Returned in the order the specification writes them, `(ct, ss)`, which is the REVERSE of
    the library's `(ss, ct)`. Normalised here rather than at each call site: a fixture with the
    two swapped is 1 088 bytes of plausible hex in a 32-byte field and would be caught, but the
    32/1088 confusion in the other direction would not be.
    """
    assert len(m) == 32, f"m is 32 bytes, got {len(m)}"
    ss, ct = _ML_KEM_768._encaps_internal(ek, m)
    return ct, ss


def kem_decaps(dz: bytes, ct: bytes) -> bytes:
    """`ML-KEM.Decaps(dk, ct)` -> `ss`. NEVER fails: implicit rejection, per §1.

    A ciphertext addressed to somebody else yields a pseudorandom secret and no error. That is
    the property the whole ladder is shaped around, so it is stated here where an implementer
    of the generator will read it, not only in the specification.
    """
    _ek, dk = kem_keygen(dz)
    return _ML_KEM_768.decaps(dk, ct)


def kem_decaps_expanded(dk: bytes, ct: bytes) -> bytes:
    """`ML-KEM.Decaps(dk, ct)` from the EXPANDED 2 400-byte key.

    **This exists for one purpose: consuming NIST's ACVP decapsulation cases**, whose `dk` is
    the expanded form. §1 requires the 64-byte `(d, z)` seed as the representation, and the
    difference is what makes a delegated tracking key 64 bytes rather than 2 400 -- so no
    derivation in this repository takes this path, and `kem_decaps` above is the one our vectors
    use.

    Kept separate rather than folded into `kem_decaps` with a length switch, because a function
    that silently accepts either representation is a function through which the expanded form
    can reach a fixture. §2.1's delegated object is defined by its exact contents.
    """
    assert len(dk) == 2400, f"the expanded dk is 2 400 bytes, got {len(dk)}"
    return _ML_KEM_768.decaps(dk, ct)


def acvp_selftest(tier1: dict) -> list[str]:
    """Reproduce NIST's ACVP tuples with the installed library. Returns disagreements.

    This is what makes the dependency trustworthy for exactly what it is used for, and it runs
    on every generator invocation rather than once by hand. An empty list is agreement; the
    caller decides whether that is required or merely reported.
    """
    if not have_kem():
        return []
    bad: list[str] = []
    for c in tier1.get("keygen", []):
        ek, _dk = kem_keygen(bytes.fromhex(c["d"] + c["z"]))
        if ek.hex() != c["ek"]:
            bad.append(f"keyGen tcId {c['tcId']}: ek disagrees with ACVP")
    for c in tier1.get("encapsulation", []):
        ct, ss = kem_encaps(bytes.fromhex(c["ek"]), bytes.fromhex(c["m"]))
        if ct.hex() != c["c"]:
            bad.append(f"encaps tcId {c['tcId']}: ct disagrees with ACVP")
        if ss.hex() != c["k"]:
            bad.append(f"encaps tcId {c['tcId']}: ss disagrees with ACVP")
    # DECAPSULATION, deliberately. Without it a KEM with correct
    # keygen and encapsulation for the sampled cases, and a subtly wrong decapsulation path,
    # would pass the advertised oracle -- while `V2-11` and `V2-13` are emitted THROUGH
    # decapsulation. Five of these cases are `modified ciphertext`, which is IMPLICIT REJECTION
    # against NIST's own expected secret: the property the ladder is shaped around, and this
    # is its only external check.
    for c in tier1.get("decapsulation", []):
        ss = kem_decaps_expanded(bytes.fromhex(c["dk"]), bytes.fromhex(c["c"]))
        if ss.hex() != c["k"]:
            bad.append(f"decaps tcId {c['tcId']} ({c['reason']}): ss disagrees with ACVP")
    return bad
DS_KEYGEN = b"pq-stealth/keygen/v1"
DS_SENDER = b"pq-stealth/sender-seed/v1"


def reduce_to_scalar(base: bytes) -> tuple[int, int]:
    """§1's counter-based reduction. Returns `(scalar, counter)`.

    The bound is a **failure**, not an unbounded retry: `counter = 0` contributes no counter
    byte at all, and counters 1 to 256 contribute byte values `0x01`..`0xFF` then `0x00` -- 257
    distinct inputs, none repeated -- so a 257th iteration would re-derive the `0x01` candidate
    already rejected. Raises `ValueError` at exhaustion.

    Big-endian, which V1-02 exists to pin: a little-endian read gives a different scalar,
    therefore a different address, therefore funds the recipient cannot spend. Silent and total.
    """
    candidate = int.from_bytes(base, "big")
    if 0 < candidate < N:
        return candidate, 0
    for counter in range(1, 257):
        digest = hashlib.sha256(DS_OFFSET + base + bytes([counter & 0xFF])).digest()
        candidate = int.from_bytes(digest, "big")
        if 0 < candidate < N:
            return candidate, counter
    raise ValueError("257 candidates exhausted")


def h_of_ss(ss: bytes) -> tuple[bytes, int, int]:
    """§1's `H(ss)`. Returns `(base, scalar, counter)`."""
    base = hashlib.sha256(DS_OFFSET + ss).digest()
    scalar, counter = reduce_to_scalar(base)
    return base, scalar, counter


VIEW_TAG_BYTES = 1


def view_tag(ss: bytes) -> bytes:
    """§1's view tag: a **separate digest**, its first `VIEW_TAG_BYTES` bytes.

    **One byte, returned as `bytes` and not as an `int`.** The width is a parameter and has
    already moved once -- it was eight bytes until the announced `stealthAddress` was made
    the authoritative check (§2.4) and the tag was narrowed to a prefilter. An `int` return
    would let every call site format the value itself, and a call site formatting a widened
    tag as `f"{tag:02x}"` would emit two hex characters of it: a truncation that produces a
    well-formed fixture nobody can pass. `bytes` makes the width the primitive's business
    and a formatting mistake a type error.

    V1-07's `wrong` column names the errors it distinguishes: taking other than `[0]` alone;
    taking the trailing bytes; and taking the leading bytes of `H(ss)` rather than of this
    separate digest.
    """
    return hashlib.sha256(DS_VIEWTAG + ss).digest()[:VIEW_TAG_BYTES]


def hkdf_sha256(ikm: bytes, info: bytes, length: int, salt: bytes = b"") -> bytes:
    """HKDF-SHA256, RFC 5869, with an **absent** salt by default.

    §5's keygen derivation is HKDF and legitimately has an `info` parameter -- which is worth
    saying here because §2.9's and §3's combiners are a direct `SHA3-256` hash and have none,
    and conflating the two is the kind of error that propagates to every document quoting either.
    """
    import hmac
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def keygen_seed(master: bytes, scheme_id: int, rung: bytes, j: int, length: int) -> bytes:
    """§5's keygen-seed derivation, per V6-01.

    `ikm = keygen_master`, **salt absent**, `info = DS ‖ u64be(schemeId) ‖ u64be(|rung|) ‖ rung
    ‖ u64be(j)`, and `L` is the seed length rather than a fixed 32.

    > **The parameter placement is the whole function.** Passing the master as the
    > SALT with an empty IKM is the opposite of what §5 specifies -- which is `ikm =
    > keygen_master(32)` and `salt = absent` -- and yields a V6-01 seed starting `fac38ad9`
    > where the committed one starts `0b696cff`. An implementation making that swap fails the
    > vector, and one following a vector generated that way would derive different recovery
    > keys: seed-only recovery restores meta-addresses that never held funds and cannot see
    > the ones that do. V6-01's own `wrong` column names "a supplied salt" as an error.
    """
    info = (DS_KEYGEN
            + scheme_id.to_bytes(8, "big")
            + len(rung).to_bytes(8, "big")
            + rung
            + j.to_bytes(8, "big"))
    return hkdf_sha256(master, info, length)


def kem_id(name: bytes = KEM_NAME) -> bytes:
    """§5's `kem_id` for a bare KEM: `u64be(|name|) || name`.

    Structural rather than a flat label, because a wrapper embeds the identifier of what it
    wraps rather than replacing it, and every component is length-prefixed so that no two
    nestings serialise alike. Only the bare form is needed here; the deployed path is
    `u64be(10) || "ML-KEM-768"`, 18 bytes.
    """
    return len(name).to_bytes(8, "big") + name


def announce_seed(master: bytes, scheme_id: int, rung: bytes, i: int, length: int,
                  kem: bytes | None = None) -> bytes:
    """§5's announce-seed derivation.

    ```
    seed_i = SHAKE256(DS || master(32) || u64be(i)
                      || u64be(schemeId) || u64be(|rung|) || rung
                      || u64be(|kem_id|) || kem_id, n)
    ```

    The rung is bound as well as the `schemeId`, and binding the id alone is **not
    sufficient**: the three schemeId 6 levels share an id and a seed length, so one master and
    counter would give all three the byte-identical KEM message. **And the KEM is bound as
    well as the rung**, because the same rung over two KEMs is two different things that MUST
    NOT share a seed stream, and naming a wrapper does not distinguish them.

    > **Two transpositions matter here, and V6-05 pins both.** Appending `i` LAST where §5
    > puts it immediately after `master`, or omitting
    > `kem_id` **entirely** -- either alone changes every announce seed: a sender
    > following §5 and a sender making the swap draw different ephemeral keys and
    > different KEM messages from the same master and index, so a conformance vector generated
    > that way would fail every conforming implementation while passing itself.
    >
    > A string-shape gate cannot catch either: every constant here
    > is quoted correctly from the specification, and the ORDER is what carries the claim.
    """
    return hashlib.shake_256(
        DS_SENDER + master + i.to_bytes(8, "big")
        + scheme_id.to_bytes(8, "big")
        + len(rung).to_bytes(8, "big") + rung
        + len(kem_id() if kem is None else kem).to_bytes(8, "big")
        + (kem_id() if kem is None else kem)
    ).digest(length)
