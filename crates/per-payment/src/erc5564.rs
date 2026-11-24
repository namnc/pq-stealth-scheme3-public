//! ERC-5564's three methods for `schemeId` 3, as §2.8 defines them, over bytes.
//!
//! Each takes what ERC-5564's signature takes. `viewingKey` is the 96-byte tracking key and
//! comes in whole on every call, so every call recomputes `viewing_pk_ec` and `ek` from it.
//! A wallet scanning many announcements should [`StealthScheme::bind`] once and
//! [`StealthScheme::scan`] each: `bind` also makes §2.5's comparison with the registered
//! meta-address, which these methods have no meta-address to make.
//!
//! `viewingKey`, `spendingPubKey` and `spendingKey` are the caller's own keys, so a malformed one
//! is an error in every method, never `false`. Announcement bytes that §2.7 makes a skip are
//! `Ok(false)` in [`check_stealth_address`].

use crate::{
    MlKem768Suite, Scanner, SchemeId3, SpendKey, match_from_secret, parse_ephemeral_pub_key,
    payment_secret, spend_key_from, view_tag_of,
};
use pqsa_core::{Bytes32, Error, StealthScheme, VIEW_TAG_BYTES};
use pqsa_ec::CompressedPoint;
use pqsa_kem::{Kem, MlKem768};

/// `viewingKey` length: the tracking key `viewing_ec ‖ d ‖ z`. §2.1.
pub const VIEWING_KEY_BYTES: usize = 32 + MlKem768::KEYGEN_SEED_BYTES;

/// What `generateStealthAddress` returns: `(stealthAddress, ephemeralPubKey, viewTag)`.
pub type GeneratedStealthAddress = ([u8; 20], Vec<u8>, [u8; VIEW_TAG_BYTES]);

/// `generateStealthAddress(stealthMetaAddress)`: §2.4, with `esk` and `m` from the operating
/// system's CSPRNG.
///
/// # Errors
///
/// [`Error::Malformed`] if `stealth_meta_address` does not decode (§2.2); [`Error::Kem`] if its
/// `ek` fails FIPS 203's encapsulation key check; [`Error::Rng`] if the RNG fails.
pub fn generate_stealth_address(
    stealth_meta_address: &[u8],
) -> Result<GeneratedStealthAddress, Error> {
    let meta = SchemeId3::meta_from_bytes(stealth_meta_address).ok_or(Error::Malformed)?;
    let ann = SchemeId3::announce_random(&meta)?;
    let (stealth_address, ephemeral_pub_key, _) = SchemeId3::announcement_to_bytes(&ann);
    Ok((stealth_address, ephemeral_pub_key, ann.view_tag))
}

/// `checkStealthAddress(stealthAddress, ephemeralPubKey, viewingKey, spendingPubKey)`: §2.5
/// with no view tag to compare, so the derived address alone decides.
///
/// `Ok(false)` wherever §2.7 says skip, a malformed `ephemeralPubKey` included.
///
/// # Errors
///
/// [`Error::Malformed`] if `viewing_key` is not [`VIEWING_KEY_BYTES`] or `spending_pub_key` is
/// not a valid compressed point; [`Error::NoValidScalar`] if `viewing_ec` is not a valid scalar.
pub fn check_stealth_address(
    stealth_address: &[u8; 20],
    ephemeral_pub_key: &[u8],
    viewing_key: &[u8],
    spending_pub_key: &[u8],
) -> Result<bool, Error> {
    let scanner = scanner_from(viewing_key, pqsa_ec::decode_point(spending_pub_key)?)?;
    let Some((epk, ct)) = parse_ephemeral_pub_key::<MlKem768Suite>(ephemeral_pub_key) else {
        return Ok(false);
    };
    let Some(ss) = payment_secret(&scanner, &epk, ct) else {
        return Ok(false);
    };
    // The derived tag stands in for the announced one, which ERC-5564 does not pass here.
    Ok(match_from_secret(&ss, &scanner.spending, &view_tag_of(&ss), stealth_address).is_some())
}

/// `computeStealthKey(stealthAddress, ephemeralPubKey, viewingKey, spendingKey)`: §2.6.
///
/// Fails rather than return a key that does not control `stealth_address`.
///
/// # Errors
///
/// As [`check_stealth_address`] for `viewing_key`; [`Error::Malformed`] if `spending_key` is not
/// 32 bytes or `ephemeral_pub_key` is malformed; [`Error::NoValidScalar`] if `spending_key` is
/// not a valid scalar; [`Error::MasterKeyMismatch`] if the key derived from these inputs does
/// not control `stealth_address`.
pub fn compute_stealth_key(
    stealth_address: &[u8; 20],
    ephemeral_pub_key: &[u8],
    viewing_key: &[u8],
    spending_key: &[u8],
) -> Result<SpendKey, Error> {
    let spending_seed: &Bytes32 = spending_key.try_into().map_err(|_| Error::Malformed)?;
    let scanner = scanner_from(viewing_key, pqsa_ec::public_point(spending_seed)?)?;
    let (epk, ct) =
        parse_ephemeral_pub_key::<MlKem768Suite>(ephemeral_pub_key).ok_or(Error::Malformed)?;
    let shared_secret = payment_secret(&scanner, &epk, ct).ok_or(Error::Malformed)?;
    spend_key_from(spending_seed, &shared_secret, stealth_address)
}

/// The scanner §2.8 describes: `viewing_pk_ec` and `ek` recomputed from `viewing_key`, and
/// nothing to compare them with.
fn scanner_from(viewing_key: &[u8], spending: CompressedPoint) -> Result<Scanner, Error> {
    if viewing_key.len() != VIEWING_KEY_BYTES {
        return Err(Error::Malformed);
    }
    let (viewing_ec, kem_seed) = viewing_key.split_at(32);
    let viewing_ec_seed: &Bytes32 = viewing_ec.try_into().map_err(|_| Error::Malformed)?;
    let viewing_pk_ec = pqsa_ec::public_point(viewing_ec_seed)?;
    let (ek, kem_seed) = MlKem768::keygen(kem_seed)?;
    Ok(Scanner {
        dk: MlKem768::decapsulation_key(&kem_seed)?,
        viewing_ec_seed: (*viewing_ec_seed).into(),
        ek,
        viewing_pk_ec,
        spending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Master, MetaAddress, Tracking};
    use secrecy::ExposeSecret;

    struct Recipient {
        meta: MetaAddress,
        master: Master,
        tracking: Tracking,
        meta_bytes: Vec<u8>,
        viewing_key: Vec<u8>,
        spending_pub_key: Vec<u8>,
    }

    fn recipient(seed: &[u8]) -> Recipient {
        let (meta, master, tracking) = SchemeId3::keygen(seed).expect("valid seed");
        let mut viewing_key = tracking
            .viewing_ec_seed
            .as_ref()
            .expect("schemeId 3")
            .to_vec();
        viewing_key.extend_from_slice(&tracking.kem_seed);
        Recipient {
            meta_bytes: SchemeId3::meta_to_bytes(&meta),
            spending_pub_key: meta.spending.as_bytes().to_vec(),
            meta,
            master,
            tracking,
            viewing_key,
        }
    }

    /// The demonstration's keygen seed.
    fn ours() -> Recipient {
        recipient(
            &(0..128u8)
                .map(|i| i.wrapping_mul(7).wrapping_add(3))
                .collect::<Vec<_>>(),
        )
    }

    fn theirs() -> Recipient {
        recipient(&[[0x21u8; 32].as_slice(), &[0x42; 32], &[0x63; 64]].concat())
    }

    #[test]
    fn generate_check_and_compute_agree_with_scan_and_spend_key() {
        let r = ours();
        assert_eq!(r.viewing_key.len(), VIEWING_KEY_BYTES);
        let (address, ephemeral_pub_key, view_tag) =
            generate_stealth_address(&r.meta_bytes).expect("a valid meta-address");
        assert_eq!(
            check_stealth_address(
                &address,
                &ephemeral_pub_key,
                &r.viewing_key,
                &r.spending_pub_key
            ),
            Ok(true)
        );
        let key = compute_stealth_key(
            &address,
            &ephemeral_pub_key,
            &r.viewing_key,
            r.master.spending_seed.as_slice(),
        )
        .expect("our payment");
        let pk = pqsa_ec::public_point(key.expose_secret()).expect("a valid scalar");
        assert_eq!(pqsa_ec::address_of(&pk), address);

        // The same payment through the scheme's own interface, view tag included.
        let ann = SchemeId3::announcement_from_bytes(&address, &ephemeral_pub_key, &view_tag)
            .expect("well-formed");
        let scanner = SchemeId3::bind(&r.tracking, &r.meta).expect("matching keys");
        let m = SchemeId3::scan(&scanner, &ann).expect("the view tag and the address match");
        assert_eq!(
            SchemeId3::spend_key(&r.master, &m).unwrap().expose_secret(),
            key.expose_secret()
        );
    }

    #[test]
    fn someone_elses_payment_is_false_and_has_no_key() {
        let (r, other) = (ours(), theirs());
        let (address, ephemeral_pub_key, _) = generate_stealth_address(&other.meta_bytes).unwrap();
        assert_eq!(
            check_stealth_address(
                &address,
                &ephemeral_pub_key,
                &r.viewing_key,
                &r.spending_pub_key
            ),
            Ok(false)
        );
        assert_eq!(
            compute_stealth_key(
                &address,
                &ephemeral_pub_key,
                &r.viewing_key,
                r.master.spending_seed.as_slice()
            )
            .unwrap_err(),
            Error::MasterKeyMismatch
        );
        // The intended recipient's keys see it.
        assert_eq!(
            check_stealth_address(
                &address,
                &ephemeral_pub_key,
                &other.viewing_key,
                &other.spending_pub_key
            ),
            Ok(true)
        );
    }

    /// No view tag is passed, so nothing but the address can decide.
    #[test]
    fn the_address_decides() {
        let r = ours();
        let (address, ephemeral_pub_key, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        let mut other_address = address;
        other_address[19] ^= 1;
        assert_eq!(
            check_stealth_address(
                &other_address,
                &ephemeral_pub_key,
                &r.viewing_key,
                &r.spending_pub_key
            ),
            Ok(false)
        );
        assert_eq!(
            compute_stealth_key(
                &other_address,
                &ephemeral_pub_key,
                &r.viewing_key,
                r.master.spending_seed.as_slice()
            )
            .unwrap_err(),
            Error::MasterKeyMismatch,
            "no key for an address these inputs do not pay"
        );
    }

    /// §2.7's skips are `false` in the check and errors in the key computation, which is only
    /// called after a match.
    #[test]
    fn a_malformed_ephemeral_pub_key_is_false_not_an_error() {
        let r = ours();
        let (address, honest, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        let mut shapes: Vec<Vec<u8>> = [0, 33, 1120, 1122]
            .iter()
            .map(|&len| {
                let mut field = honest.clone();
                field.resize(len, 0x11);
                field
            })
            .collect();
        for tag in [0x00, 0x04, 0x05] {
            let mut field = honest.clone();
            field[0] = tag;
            shapes.push(field);
        }
        let mut x_5 = honest.clone();
        x_5[..33].copy_from_slice(&[[0x02u8].as_slice(), &[0; 31], &[5]].concat());
        shapes.push(x_5);

        for field in shapes {
            assert_eq!(
                check_stealth_address(&address, &field, &r.viewing_key, &r.spending_pub_key),
                Ok(false),
                "{} bytes, tag {:02x?}",
                field.len(),
                field.first()
            );
            assert_eq!(
                compute_stealth_key(
                    &address,
                    &field,
                    &r.viewing_key,
                    r.master.spending_seed.as_slice()
                )
                .unwrap_err(),
                Error::Malformed
            );
        }
    }

    /// The caller's own keys are not announcement data: `false` would hide a broken key behind
    /// a scan that finds nothing.
    #[test]
    fn a_malformed_key_of_the_callers_is_an_error() {
        let r = ours();
        let (address, epk, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        let check = |vk: &[u8], spk: &[u8]| check_stealth_address(&address, &epk, vk, spk);
        let compute = |vk: &[u8], sk: &[u8]| compute_stealth_key(&address, &epk, vk, sk);
        let (vk, spk, sk) = (
            r.viewing_key.as_slice(),
            r.spending_pub_key.as_slice(),
            r.master.spending_seed.as_slice(),
        );

        for len in [0, 64, 95, 97, 128] {
            let mut bad = vk.to_vec();
            bad.resize(len, 0x11);
            assert_eq!(
                check(&bad, spk),
                Err(Error::Malformed),
                "viewingKey {len} B"
            );
            assert_eq!(
                compute(&bad, sk).unwrap_err(),
                Error::Malformed,
                "viewingKey {len} B"
            );
        }
        for viewing_ec in [[0u8; 32], [0xff; 32]] {
            let bad = [viewing_ec.as_slice(), &vk[32..]].concat();
            assert_eq!(check(&bad, spk), Err(Error::NoValidScalar));
            assert_eq!(compute(&bad, sk).unwrap_err(), Error::NoValidScalar);
        }

        let mut compact = spk.to_vec();
        compact[0] = 0x05;
        for bad in [compact.as_slice(), &spk[..32], &[]] {
            assert_eq!(check(vk, bad), Err(Error::Malformed));
        }

        assert_eq!(compute(vk, &sk[..31]).unwrap_err(), Error::Malformed);
        assert_eq!(compute(vk, &[0u8; 32]).unwrap_err(), Error::NoValidScalar);
        assert_eq!(compute(vk, &[0xff; 32]).unwrap_err(), Error::NoValidScalar);
    }

    #[test]
    fn generate_rejects_what_decoding_rejects() {
        let r = ours();
        for len in [0, 1249, 1251] {
            let mut bad = r.meta_bytes.clone();
            bad.resize(len, 0);
            assert_eq!(
                generate_stealth_address(&bad),
                Err(Error::Malformed),
                "{len} B"
            );
        }
        let mut bad = r.meta_bytes.clone();
        bad[33] = 0x05;
        assert_eq!(generate_stealth_address(&bad), Err(Error::Malformed));
    }

    /// What §2.8 warns about: with no meta-address to compare against, a corrupted `viewingKey`
    /// is not an error, it is a scan that never matches. `bind` catches the same corruption.
    #[test]
    fn a_corrupted_viewing_key_finds_nothing_and_only_bind_says_why() {
        let r = ours();
        let (address, epk, _) = generate_stealth_address(&r.meta_bytes).unwrap();
        let mut corrupted = r.viewing_key.clone();
        corrupted[40] ^= 1;
        assert_eq!(
            check_stealth_address(&address, &epk, &corrupted, &r.spending_pub_key),
            Ok(false)
        );
        let tracking = Tracking {
            viewing_ec_seed: r.tracking.viewing_ec_seed,
            kem_seed: corrupted[32..].to_vec().into(),
        };
        assert!(matches!(
            SchemeId3::bind(&tracking, &r.meta),
            Err(Error::TrackingKeyMismatch)
        ));
    }
}
