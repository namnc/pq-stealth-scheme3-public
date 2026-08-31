//! secp256k1: one SEC1 decoder, ECDH (x-coordinate), scalar/point add, Ethereum address.
//!
//! [`decode_point`] accepts only compressed `0x02`/`0x03`. `k256` also accepts SEC1 compact
//! `0x05` and canonicalises it to the same point, so two encodings would be two meta-addresses
//! for one key. Tag checks run before handing bytes to `k256`. §2.2.
//!
//! Constant-time: not claimed. Tag/length checks are on public wire bytes. Scalars in
//! [`ecdh`] and [`add_scalars`] go through `k256`. No signing here.

use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::{Group, GroupEncoding};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{AffinePoint, ProjectivePoint, Scalar};
use pqsa_core::{Bytes32, Error};
use sha3::{Digest, Keccak256};

/// SEC1 compressed even-`y` tag. §2.2.
const TAG_EVEN: u8 = 0x02;
/// The odd-`y` compressed tag.
const TAG_ODD: u8 = 0x03;

/// 32-byte big-endian scalar. Rejects 0 and values ≥ n; does not reduce modulo n. §1.
fn scalar_of(bytes: &Bytes32) -> Result<Scalar, Error> {
    // `from_repr` is None at or above n, not a reduction.
    let s =
        Option::<Scalar>::from(Scalar::from_repr((*bytes).into())).ok_or(Error::NoValidScalar)?;
    if s.is_zero().into() {
        return Err(Error::NoValidScalar);
    }
    Ok(s)
}

/// SEC1 compressed point (`0x02`/`0x03` + 32-byte x). Only [`decode_point`] / [`public_point`] construct this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressedPoint([u8; 33]);

impl CompressedPoint {
    /// 33 wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// Decode a SEC1 compressed point. Accepts only `0x02`/`0x03`. §2.2.
///
/// Rejects uncompressed (`0x04`), compact (`0x05`), wrong length, and off-curve / out-of-range
/// x. Every rejection is [`Error::Malformed`] (no per-cause variant).
///
/// # Errors
///
/// [`Error::Malformed`] for any rejected encoding.
pub fn decode_point(bytes: &[u8]) -> Result<CompressedPoint, Error> {
    // Tag/length before `k256`: its decoder accepts compact `0x05` and canonicalises it.
    let fixed: [u8; 33] = bytes.try_into().map_err(|_| Error::Malformed)?;
    if fixed[0] != TAG_EVEN && fixed[0] != TAG_ODD {
        return Err(Error::Malformed);
    }
    let _point = Option::<AffinePoint>::from(AffinePoint::from_bytes(&fixed.into()))
        .ok_or(Error::Malformed)?;
    Ok(CompressedPoint(fixed))
}

/// Compressed public point of `scalar`.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if the scalar is 0 or ≥ n.
pub fn public_point(scalar: &Bytes32) -> Result<CompressedPoint, Error> {
    let s = scalar_of(scalar)?;
    let affine = (ProjectivePoint::GENERATOR * s).to_affine();
    let enc = affine.to_encoded_point(true);
    let out: [u8; 33] = enc.as_bytes().try_into().map_err(|_| Error::Malformed)?;
    Ok(CompressedPoint(out))
}

/// ECDH: 32-byte **x-coordinate** of `scalar · point`. Not the compressed or uncompressed
/// point. §1.1, §2.4, V3-04.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if `scalar` is 0 or ≥ n.
pub fn ecdh(scalar: &Bytes32, point: &CompressedPoint) -> Result<Bytes32, Error> {
    let s = scalar_of(scalar)?;
    let p = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*point.as_bytes()).into()))
        .ok_or(Error::Malformed)?;
    let shared = (ProjectivePoint::from(p) * s).to_affine();
    // x from uncompressed (0x04 || x || y); compressed [1..33] is the same x but easy to
    // confuse with including the parity tag.
    let enc = shared.to_encoded_point(false);
    let bytes = enc.as_bytes();
    debug_assert_eq!(bytes.len(), 65, "uncompressed SEC1 is 0x04 || x || y");
    let x: Bytes32 = bytes[1..33].try_into().map_err(|_| Error::Malformed)?;
    Ok(x)
}

/// `scalar + offset` mod n. §2.3.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if either input is not in `1..n`, or if the sum is 0.
pub fn add_scalars(scalar: &Bytes32, offset: &Bytes32) -> Result<Bytes32, Error> {
    let a = scalar_of(scalar)?;
    let b = scalar_of(offset)?;
    let sum = a + b;
    if sum.is_zero().into() {
        return Err(Error::NoValidScalar);
    }
    Ok(sum.to_bytes().into())
}

/// Point addition. Sender/scanner side of §2.3: `spending_pk + offset·G`.
///
/// # Errors
///
/// [`Error::Malformed`] if the sum is the identity (which has no compressed encoding).
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

/// Ethereum address: low 20 bytes of keccak256(uncompressed x‖y), no `0x04` prefix. V2-09.
#[must_use]
pub fn address_of(point: &CompressedPoint) -> [u8; 20] {
    // Invariant: only decode_point / public_point construct CompressedPoint.
    let p = Option::<AffinePoint>::from(AffinePoint::from_bytes(&(*point.as_bytes()).into()))
        .expect("a CompressedPoint has been through decode_point or public_point");
    let enc = p.to_encoded_point(false);
    let digest = Keccak256::digest(&enc.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("test fixture is hex")
    }

    fn hexlify(b: &[u8]) -> String {
        hex::encode(b)
    }

    fn b32(s: &str) -> Bytes32 {
        unhex(s).try_into().unwrap()
    }

    /// V2-07: compact `0x05` rejected; same x is valid as `0x03`.
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
            "identical x; only the tag differs"
        );
    }

    /// Wrong length, uncompressed, off-curve x.
    #[test]
    fn decode_point_rejects_the_rest() {
        for bad in [
            vec![],
            vec![0x02; 32],
            vec![0x02; 34],
            [vec![0x04u8], vec![0x11; 64]].concat(),
            [vec![0x02u8], vec![0xff; 32]].concat(),
            // V3-12: x = 5 is on no secp256k1 point.
            unhex("020000000000000000000000000000000000000000000000000000000000000005"),
        ] {
            assert!(
                matches!(decode_point(&bad), Err(Error::Malformed)),
                "{} bytes tagged {:02x?} must be rejected",
                bad.len(),
                bad.first()
            );
        }
    }

    /// ECDH returns the 32-byte x-coordinate. SchemeId 3 pins the same operation to V3-04.
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
    }

    /// ECDH commutes.
    #[test]
    fn ecdh_agrees_from_both_sides() {
        let esk = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let vsk = b32("3333333333333333333333333333333333333333333333333333333333333333");
        let epk = public_point(&esk).unwrap();
        let vpk = public_point(&vsk).unwrap();
        assert_eq!(ecdh(&esk, &vpk).unwrap(), ecdh(&vsk, &epk).unwrap());
    }

    /// V2-09: keccak256(x‖y)[12..32], not prefix / first-20 / SHA3-256.
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

    /// n and 0 rejected; n−1 accepted.
    #[test]
    fn a_scalar_at_the_order_is_rejected_not_reduced() {
        let n = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        assert!(matches!(public_point(&b32(n)), Err(Error::NoValidScalar)));
        assert!(matches!(
            public_point(&[0u8; 32]),
            Err(Error::NoValidScalar)
        ));
        let n_minus_1 = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        assert!(public_point(&b32(n_minus_1)).is_ok());
    }

    /// `(n-1) + 2 ≡ 1 (mod n)`.
    #[test]
    fn add_scalars_reduces_modulo_the_order() {
        let n_minus_1 = b32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        let two = b32("0000000000000000000000000000000000000000000000000000000000000002");
        let one = b32("0000000000000000000000000000000000000000000000000000000000000001");
        assert_eq!(add_scalars(&n_minus_1, &two).unwrap(), one);
    }

    /// `(s + h)·G == s·G + h·G`, checked directly through `k256` without this crate's wrappers.
    #[test]
    fn the_sender_and_recipient_derive_one_point() {
        let spending = b32("1111111111111111111111111111111111111111111111111111111111111111");
        let offset = b32("2222222222222222222222222222222222222222222222222222222222222222");
        let stealth_sk = add_scalars(&spending, &offset).unwrap();
        let from_secret = public_point(&stealth_sk).unwrap();

        let from_points = add_points(
            &public_point(&spending).unwrap(),
            &public_point(&offset).unwrap(),
        )
        .unwrap();

        // Bypass this crate's wrappers so both public paths are checked against the library.
        let s = Option::<Scalar>::from(Scalar::from_repr(spending.into())).unwrap();
        let h = Option::<Scalar>::from(Scalar::from_repr(offset.into())).unwrap();
        let expected = ((ProjectivePoint::GENERATOR * s) + (ProjectivePoint::GENERATOR * h))
            .to_affine()
            .to_encoded_point(true);

        assert_eq!(from_secret.as_bytes(), expected.as_bytes());
        assert_eq!(from_points.as_bytes(), expected.as_bytes());
    }
}
