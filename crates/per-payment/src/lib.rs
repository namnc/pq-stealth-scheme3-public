//! schemeId 3 (ECDH + ML-KEM), one announcement per payment.
//!
//! The scheme is specified in §2; §1 gives the offset and view-tag derivation it shares with
//! anything else built on ERC-5564. Spending is secp256k1 ECDSA. What the hybrid does and
//! does not give is in §5.
//!
use pqsa_core::{
    Bytes32, Error, ExportableSpendKey, StealthScheme, VIEW_TAG_BYTES,
    reject_if_spending_key_is_delegated,
};
use pqsa_ec::CompressedPoint;
use pqsa_kem::{Kem, MlKem768};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// Offset domain separator. First input to the hash, never appended. §1.
const DS_OFFSET: &[u8] = b"pq-stealth/offset/v1";

/// View-tag domain separator. Separate digest from the offset (V1-07).
const DS_VIEWTAG: &[u8] = b"pq-stealth/view-tag/v1";
/// schemeId 3: payment secret combines ECDH and KEM secrets. §2.
pub struct SchemeId3;

/// Registry blob: spending point, optional viewing point (schemeId 3), ML-KEM `ek`. §2.2 order.
#[derive(Debug, Clone)]
pub struct MetaAddress {
    /// Payments are derived against this point. Not used to scan.
    pub spending: CompressedPoint,
    /// ECDH viewing point. Always `Some` here; the `Option` is vestigial (see the note
    /// on `Tracking::viewing_ec_seed`).
    pub viewing_ec: Option<CompressedPoint>,
    /// ML-KEM-768 encapsulation key, 1 184 bytes.
    pub ek: Vec<u8>,
}

/// Recipient spending secret. Never delegated.
#[derive(Clone)]
pub struct Master {
    /// Scalar every one-time key is offset from.
    pub spending_seed: Bytes32,
    /// Viewing scalar. Always `Some` here. The `Option` is left from a KEM-only scheme that
    /// does not ship in this tree; collapsing it removes a `Malformed` path that nothing
    /// can now reach, and is a change to the public type rather than a trim.
    pub viewing_ec_seed: Option<Bytes32>,
    /// ML-KEM `(d, z)` seed (64 bytes). Not the 2400-byte expanded key.
    pub kem_seed: Vec<u8>,
}

/// Delegatable scan material. §2.1. A delegated scanner sees the whole payment graph (§9).
#[derive(Clone)]
pub struct Tracking {
    /// Viewing scalar. Always `Some` here; the `Option` is vestigial.
    pub viewing_ec_seed: Option<Bytes32>,
    /// ML-KEM `(d, z)` seed.
    pub kem_seed: Vec<u8>,
}

/// Tracking bound to a meta-address, plus values [`StealthScheme::scan`] reuses.
///
/// Only [`StealthScheme::bind`] constructs this. `ek` is recomputed from `kem_seed` and
/// checked against the registry.
#[derive(Clone)]
pub struct Scanner {
    /// The delegated `(d, z)` pair. Decapsulation's input.
    kem_seed: Vec<u8>,
    /// Viewing scalar. `Some` on schemeId 3.
    viewing_ec_seed: Option<Bytes32>,
    /// The encapsulation key **recomputed from `kem_seed` and verified** against the registry.
    ek: Vec<u8>,
    /// Viewing point, derived once at bind. `Some` on schemeId 3.
    viewing_pk_ec: Option<CompressedPoint>,
    /// The registry's spending point. Not delegated material; §2.5 needs it to derive.
    spending: CompressedPoint,
}

/// Recompute `ek` from `(d, z)` and require it equal `registered`. §1.
///
/// Both sides are public (registry vs derived).
///
/// # Errors
///
/// [`Error::Malformed`] if `kem_seed` has the wrong length;
/// [`Error::TrackingKeyMismatch`] if the recomputed key differs from `registered`.
pub fn verified_ek(kem_seed: &[u8], registered: &[u8]) -> Result<Vec<u8>, Error> {
    let (ek, _) = MlKem768::keygen(kem_seed)?;
    if ek.as_slice() != registered {
        return Err(Error::TrackingKeyMismatch);
    }
    Ok(ek)
}

/// ERC-5564 payload. §3: `epk` in `ephemeralPubKey`, `view_tag ‖ ct` in `metadata`.
#[derive(Debug, Clone)]
pub struct Announcement {
    /// schemeId 3: sender ephemeral point.
    pub epk: Option<CompressedPoint>,
    /// ML-KEM ciphertext, 1 088 bytes.
    pub ct: Vec<u8>,
    /// `metadata[0]`. Compared in full.
    pub view_tag: [u8; VIEW_TAG_BYTES],
    /// ERC-5564 `stealthAddress` for this payment. `[0u8; 20]` is a valid Ethereum address,
    /// so it cannot stand in for "missing".
    pub stealth_address: [u8; 20],
}

/// Successful scan. [`StealthScheme::spend_key`] checks that `master` controls `stealth_address`.
#[derive(Clone)]
pub struct Match {
    /// Derived stealth address. §2.4 makes the comparison against the announced
    /// `stealthAddress` a MUST and `match_from_secret` performs it, so a `Match` never
    /// carries an address that disagrees with the announcement it came from.
    pub stealth_address: [u8; 20],
    /// Payment secret for the one-time key.
    pub shared_secret: Bytes32,
}

/// Offset and view tag from the payment secret, per §1.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if §1's bounded reduction finds no valid scalar.
pub fn derive_from_shared_secret(ss: &Bytes32) -> Result<(Bytes32, [u8; VIEW_TAG_BYTES]), Error> {
    Ok((offset_of(ss)?, view_tag_of(ss)))
}

/// `SHA256(DS_viewtag ‖ ss)[0]`. Does not run offset reduction.
#[must_use]
pub fn view_tag_of(ss: &Bytes32) -> [u8; VIEW_TAG_BYTES] {
    let tag_digest = Sha256::digest([DS_VIEWTAG, ss.as_slice()].concat());
    let mut view_tag = [0u8; VIEW_TAG_BYTES];
    view_tag.copy_from_slice(&tag_digest[..VIEW_TAG_BYTES]);
    view_tag
}

/// §1 offset from `ss`. Separate from [`view_tag_of`] so a scanner can reject on the tag
/// before doing scalar reduction.
fn offset_of(ss: &Bytes32) -> Result<Bytes32, Error> {
    let base: Bytes32 = Sha256::digest([DS_OFFSET, ss.as_slice()].concat()).into();
    reduce_to_scalar(&base)
}

/// §1 scalar reduction. Digests are BE. 257 distinct candidates (`counter = 0` is unhashed
/// `base`; `1..=256` as `u8` covers every byte including 0 via wrap of 256).
///
/// ```text
/// for counter in 0..=256:
///     candidate = base  if counter == 0
///               = SHA256(DS_offset || base || u8(counter))  otherwise
///     accept if 0 < candidate < n
/// ```
fn reduce_to_scalar(base: &Bytes32) -> Result<Bytes32, Error> {
    for counter in 0u16..=256 {
        let candidate: Bytes32 = if counter == 0 {
            *base
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let byte = counter as u8;
            Sha256::digest([DS_OFFSET, base.as_slice(), &[byte]].concat()).into()
        };
        if pqsa_ec::public_point(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(Error::NoValidScalar)
}

/// SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek). Direct hash, not HKDF. §1.1.
///
/// `ss_ec` is the 32-byte x-coordinate; other fields are wire/registry encodings.
///
/// # Errors
///
/// [`Error::Malformed`] if `ct` or `ek` has the wrong length.
pub fn combine_secrets(
    domain_separator: &[u8],
    ss_ec: &Bytes32,
    ss_pq: &Bytes32,
    epk: &CompressedPoint,
    ct: &[u8],
    viewing_pk_ec: &CompressedPoint,
    ek: &[u8],
) -> Result<Bytes32, Error> {
    if ct.len() != MlKem768::CT_BYTES || ek.len() != MlKem768::EK_BYTES {
        return Err(Error::Malformed);
    }
    let mut h = Sha3_256::new();
    h.update(domain_separator);
    h.update(ss_ec);
    h.update(ss_pq);
    h.update(epk.as_bytes());
    h.update(ct);
    h.update(viewing_pk_ec.as_bytes());
    h.update(ek);
    Ok(h.finalize().into())
}

/// Shared scanner tail. Tag first (§2.5), then offset, then the stealth point, then the
/// announced address.
///
/// The one-byte tag is a prefilter and not a decision: it admits 1 foreign announcement in
/// 256. §2.4 requires the announced `stealthAddress` to be the derived one, so the address
/// comparison is what actually decides, and §2.7 makes a disagreement a **skip** rather than
/// an error — `announce()` is permissionless, so an error path here would be a DoS.
fn match_from_secret(
    ss: &Bytes32,
    spending: &CompressedPoint,
    announced_tag: &[u8; VIEW_TAG_BYTES],
    announced_address: &[u8; 20],
) -> Option<Match> {
    if view_tag_of(ss) != *announced_tag {
        return None;
    }
    let offset = offset_of(ss).ok()?;
    let stealth = add_points(spending, &offset)?;
    let stealth_address = pqsa_ec::address_of(&stealth);
    if stealth_address != *announced_address {
        return None;
    }
    Some(Match {
        stealth_address,
        shared_secret: *ss,
    })
}

/// `spending_pk + offset·G`.
fn add_points(spending: &CompressedPoint, offset: &Bytes32) -> Option<CompressedPoint> {
    let offset_point = pqsa_ec::public_point(offset).ok()?;
    pqsa_ec::add_points(spending, &offset_point).ok()
}
/// schemeId 3 combiner domain separator. §2.4.
const DS_HYBRID: &[u8] = b"pq-stealth/hybrid-payment/v1";

impl StealthScheme for SchemeId3 {
    const SCHEME_ID: u64 = 3;
    const NAME: &'static str = "schemeId 3 (direct KEM, hybrid)";
    const KEYGEN_SEED_BYTES: usize = 128;
    const ANNOUNCE_SEED_BYTES: usize = 64;

    type Meta = MetaAddress;
    type Master = Master;
    type Tracking = Tracking;
    type Announcement = Announcement;
    type Match = Match;
    type Scanner = Scanner;
    type SpendKey = Bytes32;

    /// `spending_seed(32) ‖ viewing_ec_seed(32) ‖ kem_seed(64)`. Guard scans the 96-byte concat.
    fn keygen(seed: &[u8]) -> Result<(MetaAddress, Master, Tracking), Error> {
        if seed.len() != Self::KEYGEN_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let spending_seed: Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
        let viewing_ec_seed: Bytes32 = seed[32..64].try_into().map_err(|_| Error::Malformed)?;
        let kem_seed = seed[64..].to_vec();
        let delegated = [viewing_ec_seed.as_slice(), &kem_seed].concat();
        debug_assert_eq!(pqsa_core::delegation_window_count(delegated.len()), 65);
        reject_if_spending_key_is_delegated(&spending_seed, &delegated)?;
        let spending = pqsa_ec::public_point(&spending_seed)?;
        let viewing_ec = pqsa_ec::public_point(&viewing_ec_seed)?;
        let (ek, dk_seed) = MlKem768::keygen(&kem_seed)?;
        Ok((
            MetaAddress {
                spending,
                viewing_ec: Some(viewing_ec),
                ek,
            },
            Master {
                spending_seed,
                viewing_ec_seed: Some(viewing_ec_seed),
                kem_seed: dk_seed.clone(),
            },
            Tracking {
                viewing_ec_seed: Some(viewing_ec_seed),
                kem_seed: dk_seed,
            },
        ))
    }

    /// `ephemeral_seed(32) ‖ encap_seed(32)`, then the §1.1 combiner.
    fn announce(meta: &MetaAddress, seed: &[u8]) -> Result<Announcement, Error> {
        if seed.len() != Self::ANNOUNCE_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let viewing_pk_ec = meta.viewing_ec.ok_or(Error::Malformed)?;
        let esk: Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
        // Invalid ephemeral scalar is SeedRejected (retry the next index), not NoValidScalar.
        let epk = pqsa_ec::public_point(&esk).map_err(|e| match e {
            Error::NoValidScalar => Error::SeedRejected,
            other => other,
        })?;
        let ss_ec = pqsa_ec::ecdh(&esk, &viewing_pk_ec)?;
        let (ct, ss_pq) = MlKem768::encapsulate(&meta.ek, &seed[32..])?;
        let ss = combine_secrets(
            DS_HYBRID,
            &ss_ec,
            &ss_pq,
            &epk,
            &ct,
            &viewing_pk_ec,
            &meta.ek,
        )?;
        let (offset, view_tag) = derive_from_shared_secret(&ss)?;
        let stealth = add_points(&meta.spending, &offset).ok_or(Error::Malformed)?;
        Ok(Announcement {
            epk: Some(epk),
            ct,
            view_tag,
            stealth_address: pqsa_ec::address_of(&stealth),
        })
    }

    /// ECDH + decaps + combiner. `epk` and `ct` are fresh per announcement. The long-term
    /// tracking key still decapsulates every past `ct`.
    fn scan(scanner: &Scanner, ann: &Announcement) -> Option<Match> {
        let epk = ann.epk?;
        let viewing_ec_seed = scanner.viewing_ec_seed?;
        let viewing_pk_ec = scanner.viewing_pk_ec?;
        let ss_ec = pqsa_ec::ecdh(&viewing_ec_seed, &epk).ok()?;
        let ss_pq = MlKem768::decapsulate(&scanner.kem_seed, &ann.ct).ok()?;
        let ss = combine_secrets(
            DS_HYBRID,
            &ss_ec,
            &ss_pq,
            &epk,
            &ann.ct,
            &viewing_pk_ec,
            &scanner.ek,
        )
        .ok()?;
        match_from_secret(&ss, &scanner.spending, &ann.view_tag, &ann.stealth_address)
    }

    /// Checks `ek` and the viewing point against the registry. Either mismatch is
    /// [`Error::TrackingKeyMismatch`]; missing viewing fields is [`Error::Malformed`].
    fn bind(tracking: &Tracking, meta: &MetaAddress) -> Result<Scanner, Error> {
        let viewing_ec_seed = tracking.viewing_ec_seed.ok_or(Error::Malformed)?;
        let Some(registered_viewing) = meta.viewing_ec else {
            return Err(Error::Malformed);
        };
        let viewing_pk_ec = pqsa_ec::public_point(&viewing_ec_seed)?;
        if viewing_pk_ec != registered_viewing {
            return Err(Error::TrackingKeyMismatch);
        }
        Ok(Scanner {
            ek: verified_ek(&tracking.kem_seed, &meta.ek)?,
            kem_seed: tracking.kem_seed.clone(),
            viewing_pk_ec: Some(viewing_pk_ec),
            viewing_ec_seed: Some(viewing_ec_seed),
            spending: meta.spending,
        })
    }

    fn spend_key(master: &Master, m: &Match) -> Result<Bytes32, Error> {
        spend_key_from(master, m)
    }

    fn match_address(m: &Match) -> [u8; 20] {
        m.stealth_address
    }

    /// # Panics
    ///
    /// Panics if `meta.viewing_ec` is [`None`], which violates schemeId 3's shape.
    fn meta_to_bytes(meta: &MetaAddress) -> Vec<u8> {
        let viewing = meta
            .viewing_ec
            .expect("schemeId 3 always has a viewing point");
        [
            meta.spending.as_bytes().as_slice(),
            viewing.as_bytes(),
            &meta.ek,
        ]
        .concat()
    }

    fn meta_from_bytes(bytes: &[u8]) -> Option<MetaAddress> {
        if bytes.len() != 66 + MlKem768::EK_BYTES {
            return None;
        }
        Some(MetaAddress {
            spending: pqsa_ec::decode_point(&bytes[..33]).ok()?,
            viewing_ec: Some(pqsa_ec::decode_point(&bytes[33..66]).ok()?),
            ek: bytes[66..].to_vec(),
        })
    }

    /// `ephemeralPubKey` = `epk`, `metadata` = `view_tag ‖ ct`.
    ///
    /// # Panics
    ///
    /// Panics if `ann.epk` is [`None`], which violates schemeId 3's shape.
    fn announcement_to_bytes(ann: &Announcement) -> ([u8; 20], Vec<u8>, Vec<u8>) {
        let epk = ann.epk.expect("schemeId 3 always has an ephemeral point");
        (
            ann.stealth_address,
            epk.as_bytes().to_vec(),
            [ann.view_tag.as_slice(), &ann.ct].concat(),
        )
    }

    fn announcement_from_bytes(
        stealth_address: &[u8; 20],
        epk: &[u8],
        metadata: &[u8],
    ) -> Option<Announcement> {
        if epk.len() != 33 || metadata.len() != VIEW_TAG_BYTES + MlKem768::CT_BYTES {
            return None;
        }
        Some(Announcement {
            epk: Some(pqsa_ec::decode_point(epk).ok()?),
            ct: metadata[VIEW_TAG_BYTES..].to_vec(),
            view_tag: metadata[..VIEW_TAG_BYTES].try_into().ok()?,
            stealth_address: *stealth_address,
        })
    }
}

impl ExportableSpendKey for SchemeId3 {
    fn spend_key_bytes(k: &Bytes32) -> &[u8] {
        k.as_slice()
    }
}

/// `stealth_sk = spending_sk + H(ss) mod n`. §2.6.
///
/// Returns [`Error::MasterKeyMismatch`] if that key does not control `m.stealth_address`.
/// One-time key + `ss` recovers the master; do not disclose both.
fn spend_key_from(master: &Master, m: &Match) -> Result<Bytes32, Error> {
    let offset = offset_of(&m.shared_secret)?;
    let stealth_sk = pqsa_ec::add_scalars(&master.spending_seed, &offset)?;
    let stealth_pk = pqsa_ec::public_point(&stealth_sk)?;
    if pqsa_ec::address_of(&stealth_pk) != m.stealth_address {
        return Err(Error::MasterKeyMismatch);
    }
    Ok(stealth_sk)
}

/// `Debug` that prints secrets as `[REDACTED]`. `MetaAddress` / `Announcement` stay derived.
macro_rules! redacted_debug {
    ($ty:ident, secrets: [$($sf:ident),*], shown: [$($pf:ident),*]) => {
        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut d = f.debug_struct(stringify!($ty));
                $( d.field(stringify!($pf), &self.$pf); )*
                $( d.field(stringify!($sf), &"[REDACTED]"); let _ = &self.$sf; )*
                d.finish()
            }
        }
    };
}

redacted_debug!(Master, secrets: [spending_seed, viewing_ec_seed, kem_seed], shown: []);
redacted_debug!(Tracking, secrets: [viewing_ec_seed, kem_seed], shown: []);
redacted_debug!(Scanner, secrets: [kem_seed, viewing_ec_seed], shown: [ek, viewing_pk_ec, spending]);
redacted_debug!(Match, secrets: [shared_secret], shown: [stealth_address]);

#[cfg(test)]
mod spec_vectors;

#[cfg(test)]
mod tests {
    use super::*;

    /// Spending scalar followed by the ACVP `(d, z)` KEM seed.
    const SPENDING_AND_KEM_SEED: &str = "1111111111111111111111111111111111111111111111111111111111111111\
         e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0\
         1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(s).expect("test fixture is hex")
    }

    /// SchemeId 3 seed with a viewing scalar inserted between spending and KEM material.
    fn seed128() -> Vec<u8> {
        let s = unhex(SPENDING_AND_KEM_SEED);
        let mut out = s[..32].to_vec();
        out.extend((0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)));
        out.extend_from_slice(&s[32..]);
        assert_eq!(out.len(), 128);
        out
    }

    /// Flip in the `d` half of `(d, z)` must fail `bind`.
    #[test]
    fn schemeid3_bind_catches_a_corrupt_kem_seed() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        assert!(SchemeId3::bind(&tracking, &meta).is_ok());

        let mut corrupt = tracking.clone();
        corrupt.kem_seed[3] ^= 0x40; // in the `d` half, which is what `ek` depends on
        assert!(matches!(
            SchemeId3::bind(&corrupt, &meta),
            Err(Error::TrackingKeyMismatch)
        ));
    }

    /// Right KEM seed + wrong viewing seed is still `TrackingKeyMismatch`.
    #[test]
    fn schemeid3_bind_catches_a_wrong_viewing_seed_with_the_right_kem_seed() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();

        let mut mixed = tracking.clone();
        let wrong: Bytes32 = {
            let mut b = *mixed.viewing_ec_seed.as_ref().unwrap();
            b[7] ^= 0x20; // a DIFFERENT valid scalar, not an invalid one
            b
        };
        mixed.viewing_ec_seed = Some(wrong);
        let (ek, _) = MlKem768::keygen(&mixed.kem_seed).unwrap();
        assert_eq!(ek, meta.ek, "the KEM half is untouched");
        assert!(matches!(
            SchemeId3::bind(&mixed, &meta),
            Err(Error::TrackingKeyMismatch)
        ));
    }

    /// `z` is not committed by `ek`: it does not affect valid decapsulation, but it does
    /// select the implicit-rejection secret for a foreign ciphertext.
    #[test]
    fn z_is_not_publicly_bindable_but_is_used_for_implicit_rejection() {
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();

        let mut z_corrupt = tracking.clone();
        z_corrupt.kem_seed[63] ^= 0x80; // last bit of `z`

        let (ek_good, _) = MlKem768::keygen(&tracking.kem_seed).unwrap();
        let (ek_z, _) = MlKem768::keygen(&z_corrupt.kem_seed).unwrap();
        assert_eq!(
            ek_good, ek_z,
            "ek depends on d alone -- FIPS 203 KeyGen_internal"
        );
        assert!(
            SchemeId3::bind(&z_corrupt, &meta).is_ok(),
            "and so bind accepts it, which is the gap this test records"
        );

        let ann = SchemeId3::announce(&meta, &[0x77u8; 64]).unwrap();
        let scanner_z = SchemeId3::bind(&z_corrupt, &meta).unwrap();
        let m_z = SchemeId3::scan(&scanner_z, &ann).expect("z does not affect a valid decaps");
        let m_ok = SchemeId3::scan(&SchemeId3::bind(&tracking, &meta).unwrap(), &ann).unwrap();
        assert_eq!(m_z.stealth_address, m_ok.stealth_address);
        assert_eq!(m_z.shared_secret, m_ok.shared_secret);
        assert!(SchemeId3::spend_key(&master, &m_z).is_ok());

        let (foreign_ek, _) = MlKem768::keygen(&[0x5a; 64]).unwrap();
        let (foreign_ct, _) = MlKem768::encapsulate(&foreign_ek, &[0x6b; 32]).unwrap();
        let rejected_ok = MlKem768::decapsulate(&tracking.kem_seed, &foreign_ct).unwrap();
        let rejected_z = MlKem768::decapsulate(&z_corrupt.kem_seed, &foreign_ct).unwrap();
        assert_ne!(
            rejected_ok, rejected_z,
            "different z values must produce different implicit-rejection secrets"
        );
    }

    /// Tracking from account A does not bind to meta of account B.
    #[test]
    fn a_tracking_key_from_a_different_keypair_is_rejected() {
        let mut other = seed128();
        other[40] ^= 0xff; // inside `viewing_ec_seed`, so the viewing half moves too
        let (meta_a, _, tracking_a) = SchemeId3::keygen(&seed128()).unwrap();
        let (meta_b, _, tracking_b) = SchemeId3::keygen(&other).unwrap();

        assert!(SchemeId3::bind(&tracking_a, &meta_a).is_ok());
        assert!(SchemeId3::bind(&tracking_b, &meta_b).is_ok());
        for (t, m) in [(&tracking_a, &meta_b), (&tracking_b, &meta_a)] {
            assert!(matches!(
                SchemeId3::bind(t, m),
                Err(Error::TrackingKeyMismatch)
            ));
        }
    }
    /// The schemeId 3 wire representation round-trips and remains scannable.
    #[test]
    fn schemeid3_wire_round_trip_scans() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let built = SchemeId3::announce(&meta, &[0x44u8; 64]).unwrap();
        let (addr, epk, md) = SchemeId3::announcement_to_bytes(&built);
        let parsed = SchemeId3::announcement_from_bytes(&addr, &epk, &md).unwrap();

        assert_eq!(parsed.stealth_address, built.stealth_address);
        assert_eq!(parsed.epk, built.epk);
        assert_eq!(parsed.ct, built.ct);
        assert_eq!(parsed.view_tag, built.view_tag);

        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let m = SchemeId3::scan(&scanner, &parsed).expect("our own payment");
        assert_eq!(m.stealth_address, addr);
    }

    #[test]
    fn schemeid3_announce_rejects_bad_seed_lengths_and_invalid_ephemeral_scalars() {
        let (meta, _, _) = SchemeId3::keygen(&seed128()).unwrap();
        assert!(matches!(
            SchemeId3::announce(&meta, &[0u8; 63]),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            SchemeId3::announce(&meta, &[0u8; 65]),
            Err(Error::Malformed)
        ));

        let mut seed = [0x44; 64];
        seed[..32].fill(0);
        assert!(matches!(
            SchemeId3::announce(&meta, &seed),
            Err(Error::SeedRejected)
        ));

        let order = unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        seed[..32].copy_from_slice(&order);
        assert!(matches!(
            SchemeId3::announce(&meta, &seed),
            Err(Error::SeedRejected)
        ));

        let order_minus_one =
            unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
        seed[..32].copy_from_slice(&order_minus_one);
        SchemeId3::announce(&meta, &seed).expect("n - 1 is a valid ephemeral scalar");
    }

    /// Lying announced address is a skip, not an error. §2.4 MUST, §2.7 skip (DoS).
    #[test]
    fn a_lying_announced_address_is_a_skip_and_not_an_error() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let built = SchemeId3::announce(&meta, &[0x33u8; 64]).unwrap();
        let (real, epk, md) = SchemeId3::announcement_to_bytes(&built);

        let lie: [u8; 20] = core::array::from_fn(|i| 0xa0 ^ (i as u8));
        assert_ne!(
            lie, real,
            "the lie must actually differ, or this tests nothing"
        );
        let parsed = SchemeId3::announcement_from_bytes(&lie, &epk, &md).unwrap();

        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        assert!(
            SchemeId3::scan(&scanner, &parsed).is_none(),
            "the view tag still matches -- it is a function of `ss` and the lie did not touch \
             `ct` -- so the address comparison is the only thing that can reject this, and \
             §2.4 requires it to"
        );

        // A skip and not an error: `announce()` is permissionless, so anyone can publish this
        // and a scan that aborted on it would be a DoS. The honest announcement still matches.
        let honest = SchemeId3::announcement_from_bytes(&real, &epk, &md).unwrap();
        let m = SchemeId3::scan(&scanner, &honest).expect("the scan carries on");
        assert_eq!(m.stealth_address, built.stealth_address);
    }

    /// `bind` caches the recomputed `ek`, then a payment round-trips.
    #[test]
    fn bind_caches_the_recomputed_key_and_it_round_trips_a_payment() {
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let (recomputed, _) = MlKem768::keygen(&tracking.kem_seed).unwrap();
        assert_eq!(scanner.ek, recomputed);
        assert_eq!(
            scanner.ek, meta.ek,
            "and equal to the registry, having been checked"
        );

        let ann = SchemeId3::announce(&meta, &[0x5au8; 64]).unwrap();
        let m = SchemeId3::scan(&scanner, &ann).expect("our own announcement must match");
        assert_eq!(m.stealth_address, ann.stealth_address);
        assert!(SchemeId3::spend_key(&master, &m).is_ok());
    }
    /// schemeId 3: mismatch on a foreign spending seed; same spending seed with other fields
    /// changed still spends.
    #[test]
    fn spend_key_on_schemeid3_ignores_viewing_and_kem() {
        let (meta, master_a, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let built = SchemeId3::announce(&meta, &[0x44u8; 64]).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let m = SchemeId3::scan(&scanner, &built).expect("our payment");
        let sk = SchemeId3::spend_key(&master_a, &m).unwrap();

        // Regression pins for the full call path. The primitive-level conformance oracles
        // live in `spec_vectors`.
        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        assert_eq!(
            hex(&sk),
            "cb1f6323341ae29a0ebca837b1787a5a4a6b5d11916b0b5f2905d109756c998b"
        );
        assert_eq!(
            hex(&m.stealth_address),
            "ad0f2e9dac5a0df0a31455d92c6efd330983672d"
        );

        let mut master_b = master_a.clone();
        master_b.spending_seed[31] ^= 0x01;
        assert!(matches!(
            SchemeId3::spend_key(&master_b, &m),
            Err(Error::MasterKeyMismatch)
        ));

        let mut same_spending = master_a.clone();
        same_spending.kem_seed[0] ^= 0x01;
        let mut viewing = same_spending.viewing_ec_seed.unwrap();
        viewing[0] ^= 0x01;
        same_spending.viewing_ec_seed = Some(viewing);
        assert_eq!(SchemeId3::spend_key(&same_spending, &m).unwrap(), sk);
    }

    /// A mismatched view tag is not ours.
    #[test]
    fn a_mismatched_view_tag_is_not_ours() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let mut built = SchemeId3::announce(&meta, &[0x33u8; 64]).unwrap();
        built.view_tag[0] ^= 0xff;
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        assert!(SchemeId3::scan(&scanner, &built).is_none());
    }

    /// A modified, correctly-sized ciphertext takes ML-KEM's implicit-rejection path and
    /// remains a scan miss rather than an error.
    #[test]
    fn a_modified_ciphertext_is_a_skip_end_to_end() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let original = SchemeId3::announce(&meta, &[0x33u8; 64]).unwrap();
        let mut modified = original.clone();
        modified.ct[0] ^= 1;

        let epk = modified.epk.expect("announcement has an ephemeral point");
        let viewing_seed = tracking.viewing_ec_seed.expect("schemeId 3 tracking key");
        let viewing_pk = meta.viewing_ec.expect("schemeId 3 meta-address");
        let ss_ec = pqsa_ec::ecdh(&viewing_seed, &epk).unwrap();
        let ss_pq = MlKem768::decapsulate(&tracking.kem_seed, &modified.ct)
            .expect("implicit rejection returns a pseudorandom secret");
        let rejected_ss = combine_secrets(
            DS_HYBRID,
            &ss_ec,
            &ss_pq,
            &epk,
            &modified.ct,
            &viewing_pk,
            &meta.ek,
        )
        .unwrap();
        let rejected_tag = view_tag_of(&rejected_ss);
        assert_ne!(
            rejected_tag, original.view_tag,
            "fixed fixture must exercise tag rejection"
        );

        let (offset, _) = derive_from_shared_secret(&rejected_ss).unwrap();
        let stealth = add_points(&meta.spending, &offset).unwrap();
        modified.stealth_address = pqsa_ec::address_of(&stealth);

        assert!(
            SchemeId3::scan(&scanner, &modified).is_none(),
            "the original tag must reject the modified ciphertext"
        );

        modified.view_tag = rejected_tag;
        let matched = SchemeId3::scan(&scanner, &modified)
            .expect("positive control: the rejection secret, tag and address agree");
        assert_eq!(matched.shared_secret, rejected_ss);
    }

    /// Secret fields do not appear in `Debug` as hex or decimal; public fields still print.
    #[test]
    fn redaction_leaks_no_secret() {
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let ann = SchemeId3::announce(&meta, &[0x77u8; 64]).unwrap();
        let matched = SchemeId3::scan(&scanner, &ann).expect("our own announcement");

        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        // Derived Debug prints bytes as "17, 32, 9", which leaks as thoroughly as hex.
        let dec = |b: &[u8]| -> String {
            b.iter()
                .take(8)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };

        let rendered = format!("{master:?}{tracking:?}{scanner:?}{matched:?}");
        for (what, secret) in [
            ("spending_seed", &master.spending_seed[..]),
            ("viewing_ec_seed", &tracking.viewing_ec_seed.unwrap()[..]),
            ("kem_seed", &tracking.kem_seed[..]),
            ("shared_secret", &matched.shared_secret[..]),
        ] {
            assert!(
                !rendered.contains(&hex(secret)),
                "{what} appears in Debug output as hex"
            );
            assert!(
                !rendered.contains(&dec(secret)),
                "{what} appears in Debug output as a decimal byte list"
            );
        }
        assert!(
            rendered.contains("[REDACTED]"),
            "the redaction must be visible, or a reader cannot tell a redacted field from an \
             absent one"
        );
        assert!(
            rendered.contains(&dec(&matched.stealth_address)),
            "the stealth address is public by construction and must still be shown"
        );
    }

    /// Demonstration seed still produces the same announcement payload.
    #[test]
    fn demonstration_seed_reproduces_the_announcement_payload() {
        let keygen_seed: Vec<u8> = (0..SchemeId3::KEYGEN_SEED_BYTES as u32)
            .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
            .collect();
        let (meta, _, _) = SchemeId3::keygen(&keygen_seed).unwrap();
        let mut sender = pqsa_core::SenderState::resume([0x5a; 32], 0);
        let ann = SchemeId3::announce(&meta, &sender.draw_seed::<SchemeId3>().unwrap()).unwrap();
        let (addr, epk, metadata) = SchemeId3::announcement_to_bytes(&ann);
        assert_eq!(epk.len(), 33);
        assert_eq!(metadata.len(), VIEW_TAG_BYTES + MlKem768::CT_BYTES);

        let blob: Vec<u8> = addr.iter().chain(&epk).chain(&metadata).copied().collect();
        let digest: String = Sha256::digest(&blob)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "466f7268c590a20ac3771e416034fbc8d7e13b2af953ea9672466d61ceb89eca"
        );
    }
}
