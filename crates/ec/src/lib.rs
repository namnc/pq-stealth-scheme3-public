//! secp256k1, and **one** SEC1 point decoder for the whole workspace.
//!
//! # Why this is its own crate
//!
//! Because §2.2 states the SEC1 tag restriction and requires **the same decoder** wherever a
//! registered point is read. Where the rationale is written depends on the tree: §3 in a set
//! that also specifies the pairwise-channel rung, §2.2 itself in a document specifying one
//! rung. A dependency table calling those cross-references "only comparative" is how a
//! porter ends up shipping two decoders.
//!
//! The concrete hazard is SEC1's **compact** `0x05` form: the RustCrypto stack canonicalises
//! it to the same point as the `0x02`/`0x03` compressed encodings, so a decoder that accepts
//! it gives two distinct byte strings for one key. A meta-address is content-addressed by its
//! bytes, so two encodings are two meta-addresses for one recipient, and a scanner keyed on
//! one misses payments to the other. Upstream this decoder is open-coded at four sites
//! while a shared one exists, and the two implementations disagree on `0x05`.
//!
//! One crate, one function, and the sharing is structural rather than documentary.
//!
//! # What this crate deliberately cannot do
//!
//! Sign, verify, or hash. Signing is the wallet's, and §2's spending path is plain secp256k1
//! ECDSA that needs nothing from here.
//!
//! # Status
//!
//! **Implemented against the committed conformance vectors** — which were generated,
//! reviewed and committed before any of these bodies existed, so the fixtures did not
//! come from this code.
//!
//! # Constant time
//!
//! **Not claimed, and §2.8 records that the specification states no requirement.** `k256`'s
//! scalar and projective-point arithmetic is written to be constant-time; the tag and length
//! checks in [`decode_point`] are not, and they operate on public wire bytes where that is not
//! a leak. What IS a secret here is the scalar in [`ecdh`] and [`add_scalars`], and those are
//! `k256` operations end to end.

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::{Group, GroupEncoding};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use pqsa_core::{Bytes32, Error};
use sha3::{Digest, Keccak256};

/// SEC1's compressed tags, and the ONLY two this crate accepts. §2.2.
const TAG_EVEN: u8 = 0x02;
/// The odd-`y` compressed tag.
const TAG_ODD: u8 = 0x03;

/// Read a 32-byte big-endian scalar, rejecting zero and anything at or above the group order.
///
/// §1 requires the *check* rather than a reduction, and the difference is not cosmetic:
/// reducing maps two distinct seeds to one key, so a wallet that reduces can hand two users
/// the same spending key and neither ever sees an error.
fn scalar_of(bytes: &Bytes32) -> Result<Scalar, Error> {
    // `from_repr` is the canonical form: it returns `None` for a representation at or above
    // the modulus rather than reducing it, which is the property §1 asks for.
    let s =
        Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).ok_or(Error::NoValidScalar)?;
    if s.is_zero().into() {
        return Err(Error::NoValidScalar);
    }
    Ok(s)
}

/// A secp256k1 point in SEC1 compressed form: 33 bytes, leading tag `0x02` or `0x03`.
///
/// The type exists so that "a point that has been through the decoder" is distinguishable
/// from "33 bytes somebody claims is a point", which is what §2.2's rule is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedPoint([u8; 33]);

/// The bytes, exactly as they will appear on the wire and in a meta-address.
impl CompressedPoint {
    /// Borrow the 33 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// Decode a SEC1 point, accepting **only** the `0x02` and `0x03` compressed forms.
///
/// # What it rejects, and why each matters
///
/// - **`0x04`, uncompressed, 65 bytes.** A different length and a different meta-address for
///   the same key.
/// - **`0x05`, compact.** The hazard in this crate's own documentation: canonicalised to the
///   same point by at least one widely used stack, so accepting it makes one key two
///   meta-addresses.
/// - **A 33-byte string whose x-coordinate is not on the curve**, and one whose x is at or
///   above the field modulus.
///
/// # Errors
///
/// [`Error::Malformed`] for every case above. There is deliberately no variant distinguishing
/// them: a caller that behaves differently for a bad tag than for an off-curve x is leaking
/// which check failed. **That is this implementation's choice, not a requirement** — §2.2
/// obliges rejection, one decoder for both points, and validation before use, and says nothing
/// about how many error variants a decoder exposes. A conforming implementation may well
/// distinguish them; this one does not, and a caller must not read the single variant as
/// carrying spec authority it does not have.
///
/// Specification: §2.2, which states the rule and, in a single-rung document, its rationale
/// too; in a set that also specifies the pairwise-channel rung the rationale is §3's. Cited
/// by section rather than by document, since one numbering runs across the set — and the
/// rationale is named twice here because it is the one place the section that carries it
/// depends on which documents the tree holds.
pub fn decode_point(bytes: &[u8]) -> Result<CompressedPoint, Error> {
    // The length and the tag are checked BEFORE anything is handed to `k256`, and that order is
    // the whole rule: `k256`'s SEC1 decoder accepts the compact `0x05` form and canonicalises
    // it to the same point as `0x02`, so a decoder that defers to it has already lost.
    let fixed: [u8; 33] = bytes.try_into().map_err(|_| Error::Malformed)?;
    if fixed[0] != TAG_EVEN && fixed[0] != TAG_ODD {
        return Err(Error::Malformed);
    }
    // Then the point itself: an x at or above the field modulus, or not on the curve, is
    // `None` here. One error for every case, per this function's contract.
    let _point = Option::<AffinePoint>::from(AffinePoint::from_bytes(&fixed.into()))
        .ok_or(Error::Malformed)?;
    Ok(CompressedPoint(fixed))
}

/// Derive the public point of `scalar`, in compressed form.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if `scalar` is zero or at or above the group order. §1 requires
/// the check rather than a reduction: reducing silently maps distinct seeds to one key.
pub fn public_point(scalar: &Bytes32) -> Result<CompressedPoint, Error> {
    let s = scalar_of(scalar)?;
    let affine = (ProjectivePoint::GENERATOR * s).to_affine();
    let enc = affine.to_encoded_point(true);
    let out: [u8; 33] = enc.as_bytes().try_into().map_err(|_| Error::Malformed)?;
    Ok(CompressedPoint(out))
}

/// The ECDH secret between `scalar` and `point`: **the 32-byte x-coordinate of the product**.
///
/// # Why the x-coordinate and not the point
///
/// Because §2.9 says so, in terms, and repeats it: `ss_ec` is the x-coordinate **alone**, not
/// the 65-byte uncompressed point and not the 33-byte compressed form. `vectors/PLAN.md`'s
/// V3-04 exists for exactly this and names both wrong answers, because either one gives a
/// different `ss` for the same pair — silently, and every payment then lands at an address the
/// recipient never scans for.
///
/// > **The return TYPE is load-bearing.** Returning
/// > `CompressedPoint`, with `combine_secrets` accepting one, would steer a caller into
/// > hashing 33 bytes where the specification requires 32, which is the wrong answer V3-04 was
/// > written to catch. A generator and a crate can disagree on exactly this, which is the
/// > kind of disagreement documented stubs exist to surface before there is code to fix.
///
/// # Errors
///
/// [`Error::NoValidScalar`] on an invalid scalar. A point cannot be invalid here: reaching
/// this function requires having gone through [`decode_point`].
pub fn ecdh(scalar: &Bytes32, point: &CompressedPoint) -> Result<Bytes32, Error> {
    let s = scalar_of(scalar)?;
    let p = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*point.as_bytes()).into()))
        .ok_or(Error::Malformed)?;
    let shared = (ProjectivePoint::from(p) * s).to_affine();
    // The X COORDINATE ALONE, 32 bytes, big-endian. Taken off the UNCOMPRESSED encoding so
    // that no parity byte can be included by accident: the compressed form's first byte is the
    // parity, and slicing `[1..33]` off it would look identical at a glance while `[0..32]`
    // off the uncompressed form is plainly x. V3-04 names both wrong answers.
    let enc = shared.to_encoded_point(false);
    let bytes = enc.as_bytes();
    debug_assert_eq!(bytes.len(), 65, "uncompressed SEC1 is 0x04 || x || y");
    let x: Bytes32 = bytes[1..33].try_into().map_err(|_| Error::Malformed)?;
    Ok(x)
}

/// Add `offset` to `scalar` modulo the group order — the one-time key derivation of §2.3.
///
/// # Why this is a named function rather than an inline addition
///
/// §9's argument that a leaked one-time key alone reveals nothing rests on `offset` being a
/// one-time pad over the **full scalar field**. That property belongs to this operation, and
/// putting it behind a name is where the argument can be cited.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if the sum is zero, which §1 requires be rejected rather than
/// fixed up.
pub fn add_scalars(scalar: &Bytes32, offset: &Bytes32) -> Result<Bytes32, Error> {
    let a = scalar_of(scalar)?;
    let b = scalar_of(offset)?;
    let sum = a + b;
    // The sum being zero has probability ~2^-256 and is rejected rather than fixed up, per §1.
    // Reached only if `offset == -scalar`, which a sender cannot arrange without the scalar.
    if sum.is_zero().into() {
        return Err(Error::NoValidScalar);
    }
    Ok(sum.to_bytes().into())
}

/// Add two points — `spending_pk + offset·G`, the sender's and scanner's side of §2.3.
///
/// # Why this exists beside [`add_scalars`]
///
/// Because the derivation has two sides and they MUST agree: a sender holds the recipient's
/// point and adds `offset·G` to it; the recipient holds the scalar and adds `offset` to it. One
/// gives a point directly, the other gives a point through [`public_point`], and **the identity
/// `(s + h)·G == s·G + h·G` is what makes the sender's address and the recipient's key the same
/// address.** §2.4 and §2.6 both rest on it and neither states it as a testable claim, so this
/// crate's own test does.
///
/// # Errors
///
/// [`Error::Malformed`] if the sum is the identity, which no scalar a sender can choose
/// produces without knowing the recipient's key — and which has no compressed encoding, so
/// returning one would mean inventing a point.
pub fn add_points(a: &CompressedPoint, b: &CompressedPoint) -> Result<CompressedPoint, Error> {
    let pa = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*a.as_bytes()).into()))
        .ok_or(Error::Malformed)?;
    let pb = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*b.as_bytes()).into()))
        .ok_or(Error::Malformed)?;
    let sum = ProjectivePoint::from(pa) + ProjectivePoint::from(pb);
    if sum.is_identity().into() {
        return Err(Error::Malformed);
    }
    let enc = sum.to_affine().to_encoded_point(true);
    let out: [u8; 33] = enc.as_bytes().try_into().map_err(|_| Error::Malformed)?;
    Ok(CompressedPoint(out))
}

/// The Ethereum address of a point: the low 20 bytes of `keccak256` over its **uncompressed**
/// x‖y, per the ordinary account derivation.
///
/// Stated here because the input is uncompressed while everything else in this crate is
/// compressed, which is exactly the kind of asymmetry a second implementer gets wrong.
#[must_use]
pub fn address_of(point: &CompressedPoint) -> [u8; 20] {
    // Reaching here requires a decoded point, so the affine form cannot fail; `expect` rather
    // than a silent default, because an address derived from a fallback would be a real address
    // that nobody can spend from.
    let p = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*point.as_bytes()).into()))
        .expect("a CompressedPoint has been through decode_point or public_point");
    let enc = p.to_encoded_point(false);
    // keccak256 over x || y, WITHOUT the 0x04 prefix, and the low 20 bytes of the digest.
    // Three ways to get this wrong, and V2-09 pins all three: including the prefix, taking the
    // FIRST 20 bytes, and using SHA3-256 -- which differs from Keccak by one padding byte.
    let digest = Keccak256::digest(&enc.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hexlify(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn b32(s: &str) -> Bytes32 {
        unhex(s).try_into().unwrap()
    }

    /// `V2-07`. The compact `0x05` form MUST be rejected, and the point behind it is a real
    /// point — the same point the `0x03` form encodes. That is the whole hazard: `k256` decodes
    /// both to one point, so a decoder that defers to it gives one key two meta-addresses and
    /// an attacker picks which one a recipient sees.
    #[test]
    fn v2_07_the_compact_tag_is_rejected_and_its_point_is_valid() {
        let compact = unhex("054f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        let proper = unhex("034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa");
        assert!(matches!(decode_point(&compact), Err(Error::Malformed)));
        assert!(
            decode_point(&proper).is_ok(),
            "the same point in the accepted form"
        );
        assert_eq!(
            &compact[1..],
            &proper[1..],
            "identical x — only the tag differs"
        );
    }

    /// The other rejections `decode_point` promises: wrong length, uncompressed, and 33 bytes
    /// of the right shape whose x is not on the curve.
    #[test]
    fn decode_point_rejects_the_rest() {
        for bad in [
            vec![],
            vec![0x02; 32],
            vec![0x02; 34],
            [vec![0x04u8], vec![0x11; 64]].concat(),
            [vec![0x02u8], vec![0xff; 32]].concat(),
        ] {
            assert!(
                matches!(decode_point(&bad), Err(Error::Malformed)),
                "{} bytes tagged {:02x?} must be rejected",
                bad.len(),
                bad.first()
            );
        }
    }

    /// `V3-04`: `ss_ec` is the **x-coordinate
    /// alone**, 32 bytes. Both wrong answers the fixture names are asserted against, because
    /// each is a plausible return value that changes every derived address silently.
    #[test]
    fn v3_04_ecdh_is_the_x_coordinate_alone() {
        let esk = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let vpk = decode_point(&unhex(
            "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
        ))
        .expect("a valid compressed point");
        let ss_ec = ecdh(&esk, &vpk).expect("a valid scalar and point");
        assert_eq!(
            hexlify(&ss_ec),
            "9110f8760a37d96052e3dcaf14862a147654f49f722cf213568ccef1eca2ec71"
        );
        assert_eq!(ss_ec.len(), 32);
        // The fixture's two wrong answers are the 65-byte uncompressed point and the 33-byte
        // compressed one. Both CONTAIN this x -- that is exactly why they are tempting -- so
        // what the assertions below check is the LENGTH and the leading byte, not the digits.
        for wrong in [
            "049110f8760a37d96052e3dcaf14862a147654f49f722cf213568ccef1eca2ec7134ebc7978f9147\
             0a8abcdd13332db0de3261055c06ac8ff92b75b272463c6adc",
            "029110f8760a37d96052e3dcaf14862a147654f49f722cf213568ccef1eca2ec71",
        ] {
            let w = wrong.replace(['\n', ' '], "");
            assert_ne!(
                hexlify(&ss_ec),
                w,
                "ss_ec is 32 bytes, not {} ",
                w.len() / 2
            );
            assert!(
                w.ends_with(&hexlify(&ss_ec)[..8]) || w.contains(&hexlify(&ss_ec)),
                "the wrong answers contain this x, which is what makes them plausible"
            );
        }
    }

    /// ECDH is symmetric: the sender's `esk · V` and the recipient's `v · E` are one secret.
    /// Nothing in the fixtures asserts this — the vector gives one side — and a scheme where it
    /// failed would put every payment at an address the recipient never derives.
    #[test]
    fn ecdh_agrees_from_both_sides() {
        let esk = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let vsk = b32("3333333333333333333333333333333333333333333333333333333333333333");
        let epk = public_point(&esk).unwrap();
        let vpk = public_point(&vsk).unwrap();
        assert_eq!(ecdh(&esk, &vpk).unwrap(), ecdh(&vsk, &epk).unwrap());
    }

    /// `V2-09`. The address is `keccak256(x ‖ y)[12..32]`, and the fixture names three wrong
    /// answers: keeping the `0x04` prefix, taking the first 20 bytes, and using SHA3-256 —
    /// which differs from Keccak by one padding byte. All three are asserted against.
    #[test]
    fn v2_09_the_address_derivation() {
        let pk = decode_point(&unhex(
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
        ))
        .unwrap();
        let addr = address_of(&pk);
        assert_eq!(hexlify(&addr), "19e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
        for wrong in [
            "c833993f5facd9089d0e703f81577a8626c29868",
            "969b0a11b8a56bacf1ac18f219e7e376e7c213b7",
            "396031be52ec56955bd7bf15eacdfa1a1c1fe19e",
        ] {
            assert_ne!(hexlify(&addr), wrong);
        }
    }

    /// §1 requires a scalar be CHECKED, not reduced. Zero and the group order are both
    /// rejected, and the order matters: reducing maps distinct seeds to one key, so a wallet
    /// that reduces can hand two users the same spending key with no error anywhere.
    #[test]
    fn a_scalar_at_the_order_is_rejected_not_reduced() {
        let n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        assert!(matches!(public_point(&b32(n)), Err(Error::NoValidScalar)));
        assert!(matches!(
            public_point(&[0u8; 32]),
            Err(Error::NoValidScalar)
        ));
        // One below the order is valid, which is what makes the check a boundary and not a
        // blanket refusal of large scalars.
        let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        assert!(public_point(&b32(n_minus_1)).is_ok());
    }

    /// `add_scalars` is addition modulo the order, and it wraps rather than saturating —
    /// `(n-1) + 2 = 1`. Asserted because a naive 256-bit add would overflow instead.
    #[test]
    fn add_scalars_reduces_modulo_the_order() {
        let n_minus_1 = b32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let two = b32("0000000000000000000000000000000000000000000000000000000000000002");
        let one = b32("0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(add_scalars(&n_minus_1, &two).unwrap(), one);
    }

    /// The stealth derivation's own invariant: `(s + h)·G == s·G + h·G`. This is what makes a
    /// sender's address and a recipient's key the same address, and it is the property §2.4
    /// and §2.6 both rest on without either stating it as a testable claim.
    #[test]
    fn the_sender_and_recipient_derive_one_point() {
        let spending = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let offset = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let stealth_sk = add_scalars(&spending, &offset).unwrap();
        let from_secret = public_point(&stealth_sk).unwrap();

        // The sender's side: spending_pk + offset·G, which needs point addition rather than
        // scalar addition. Done through k256 directly, because the crate deliberately exposes
        // no point-addition API -- §2.4's sender path lives in `pqsa-per-payment`.
        let spending_pk = public_point(&spending).unwrap();
        let p =
            Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*spending_pk.as_bytes()).into()))
                .unwrap();
        let o = ProjectivePoint::GENERATOR
            * Option::<Scalar>::from(Scalar::from_repr(offset.into())).unwrap();
        let sum = (ProjectivePoint::from(p) + o).to_affine();
        let enc = sum.to_encoded_point(true);

        assert_eq!(enc.as_bytes(), from_secret.as_bytes());
    }
}
