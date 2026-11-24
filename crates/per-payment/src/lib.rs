//! The hybrid construction, ECDH plus a KEM, one announcement per payment, for any [`Suite`].
//! schemeId 3 is the ML-KEM-768 suite.
//!
//! The scheme is specified in §2; §1 gives the offset and view-tag derivation it shares with
//! anything else built on ERC-5564. Spending is secp256k1 ECDSA. What the hybrid does and
//! does not give is under Security Considerations.
//!
//! A [`Suite`] is what a `schemeId` fixes on top of the construction: its id and name, the
//! KEM, and the combiner's domain separator. [`Hybrid`] implements the construction for any
//! suite; [`SchemeId3`] is [`Hybrid`] over [`MlKem768Suite`], and the unprefixed types
//! ([`MetaAddress`], [`Announcement`], [`Scanner`]) are schemeId 3's.
//!
//! Secret structs and spending keys redact `Debug`; individual [`Zeroizing`] fields do not.
//!
//! Hand the spend key to a signer by borrowing its bytes, keeping the owner alive:
//!
//! ```
//! use pqsa_core::{ExportableSpendKey, StealthScheme};
//! use pqsa_per_payment::SchemeId3;
//! use zeroize::Zeroizing;
//!
//! # fn main() -> Result<(), pqsa_core::Error> {
//! // Public example seed.
//! let seed = Zeroizing::new((0u8..128).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect::<Vec<_>>());
//! let (meta, master, tracking) = SchemeId3::keygen(&seed)?;
//! let scanner = SchemeId3::bind(&tracking, &meta)?;
//! let announcement = SchemeId3::announce_random(&meta)?;
//! let matched = SchemeId3::scan(&scanner, &announcement).expect("our payment");
//! let key = SchemeId3::spend_key(&master, &matched)?;
//! let signer_input = SchemeId3::spend_key_bytes(&key);
//! assert_eq!(signer_input.len(), 32);
//! # Ok(())
//! # }
//! ```
//!
use core::marker::PhantomData;

use pqsa_core::{
    Bytes32, Error, ExportableSpendKey, StealthScheme, VIEW_TAG_BYTES,
    reject_if_spending_key_is_delegated,
};
use pqsa_ec::CompressedPoint;
use pqsa_kem::{Kem, MlKem768};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// One-time spending key with redacted `Debug` and cleanup on drop.
pub type SpendKey = SecretBox<Bytes32>;

/// Offset domain separator. First input to the hash, never appended. §1.
const DS_OFFSET: &[u8] = b"pq-stealth/offset/v1";

/// View-tag domain separator. Separate digest from the offset (V1-07).
const DS_VIEWTAG: &[u8] = b"pq-stealth/view-tag/v1";

/// What a `schemeId` fixes on top of the hybrid construction. Everything else -- the
/// secp256k1 half, §1's offset and view tag, the wire layout of §3 -- is shared by every
/// suite.
pub trait Suite: Clone + core::fmt::Debug {
    /// ERC-5564 `schemeId`. Distinct for every suite.
    const SCHEME_ID: u64;
    /// [`StealthScheme::NAME`].
    const NAME: &'static str;
    /// The combiner's domain separator. Distinct for every suite, so no two suites derive
    /// `ss` from the same input.
    const DOMAIN_SEPARATOR: &'static [u8];
    /// The KEM, or a [`pqsa_kem::Pair`] of KEMs from different families.
    type Kem: Kem;
}

/// schemeId 3: ML-KEM-768. §2.
#[derive(Clone, Copy, Debug)]
pub struct MlKem768Suite;

impl Suite for MlKem768Suite {
    const SCHEME_ID: u64 = 3;
    const NAME: &'static str = "schemeId 3 (direct KEM, hybrid)";
    const DOMAIN_SEPARATOR: &'static [u8] = DS_HYBRID;
    type Kem = MlKem768;
}

/// The hybrid construction for suite `S`: payment secret combines ECDH and KEM secrets. §2.
pub struct Hybrid<S>(PhantomData<S>);

/// schemeId 3.
pub type SchemeId3 = Hybrid<MlKem768Suite>;

impl<S: Suite> Hybrid<S> {
    /// `ephemeralPubKey` length: `epk` (33) then `ct`. §3.
    pub const EPHEMERAL_PUB_KEY_BYTES: usize = 33 + <S::Kem as Kem>::CT_BYTES;
    /// Meta-address length: spending point, viewing point, `ek`. §2.2.
    pub const META_ADDRESS_BYTES: usize = 66 + <S::Kem as Kem>::EK_BYTES;
}

/// schemeId 3's `ephemeralPubKey` length: `epk` (33) then `ct` (1 088). §3.
pub const EPHEMERAL_PUB_KEY_BYTES: usize = 33 + MlKem768::CT_BYTES;

/// Registry blob: spending point, viewing point, the suite's `ek`. §2.2 order.
/// Construct through [`Self::new`] or [`StealthScheme::meta_from_bytes`].
#[derive(Debug, Clone)]
pub struct HybridMetaAddress<S> {
    /// Spending public key used to derive and check payment addresses.
    pub spending: CompressedPoint,
    /// ECDH viewing point. Always `Some` here; the `Option` is vestigial (see the note
    /// on `Tracking::viewing_ec_seed`).
    pub viewing_ec: CompressedPoint,
    /// Encapsulation key: 1 184 bytes of ML-KEM-768 on schemeId 3.
    ek: Vec<u8>,
    suite: PhantomData<S>,
}

/// schemeId 3's meta-address.
pub type MetaAddress = HybridMetaAddress<MlKem768Suite>;

impl<S: Suite> HybridMetaAddress<S> {
    /// Construct a meta-address, checking the encapsulation-key length.
    /// KEM key validation is deferred to encapsulation.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `ek` is not the suite KEM's `EK_BYTES`.
    pub fn new(
        spending: CompressedPoint,
        viewing_ec: CompressedPoint,
        ek: Vec<u8>,
    ) -> Result<Self, Error> {
        if ek.len() != <S::Kem as Kem>::EK_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self {
            spending,
            viewing_ec,
            ek,
            suite: PhantomData,
        })
    }

    /// Encapsulation-key bytes.
    ///
    /// ```compile_fail
    /// # use pqsa_per_payment::MetaAddress;
    /// # fn truncate(meta: &mut MetaAddress) {
    /// meta.ek.pop();
    /// # }
    /// ```
    #[must_use]
    pub fn ek(&self) -> &[u8] {
        &self.ek
    }
}

/// Recipient spending secret. Never delegated.
#[derive(Clone)]
pub struct Master {
    /// Scalar every one-time key is offset from.
    pub spending_seed: Zeroizing<Bytes32>,
    /// Viewing scalar. Always `Some` here. The `Option` is left from a KEM-only scheme that
    /// does not ship in this tree; collapsing it removes a `Malformed` path that nothing
    /// can now reach, and is a change to the public type rather than a trim.
    pub viewing_ec_seed: Option<Zeroizing<Bytes32>>,
    /// The suite KEM's keygen seed: ML-KEM's `(d, z)` (64 bytes) on schemeId 3, not the
    /// 2400-byte expanded key.
    pub kem_seed: Zeroizing<Vec<u8>>,
}

/// Delegatable scan material. §2.1. A delegated scanner sees the whole payment graph
/// (Security Considerations).
#[derive(Clone)]
pub struct Tracking {
    /// Viewing scalar. [`StealthScheme::bind`] rejects [`None`].
    pub viewing_ec_seed: Option<Zeroizing<Bytes32>>,
    /// The suite KEM's keygen seed: ML-KEM's `(d, z)` on schemeId 3.
    pub kem_seed: Zeroizing<Vec<u8>>,
}

/// Tracking bound to a meta-address, plus values [`StealthScheme::scan`] reuses.
///
/// Only [`StealthScheme::bind`] constructs this. `ek` is recomputed from `kem_seed` and
/// checked against the registry, and the decapsulation key is expanded once here rather
/// than for every announcement.
#[derive(Clone)]
pub struct HybridScanner<S: Suite> {
    /// The expanded decapsulation key. Decapsulation's input.
    dk: <S::Kem as Kem>::DecapsulationKey,
    /// Viewing scalar.
    viewing_ec_seed: Zeroizing<Bytes32>,
    /// The encapsulation key **recomputed from `kem_seed` and verified** against the registry.
    ek: Vec<u8>,
    /// Viewing point, derived once.
    viewing_pk_ec: CompressedPoint,
    /// The registry's spending point. Not delegated material; §2.5 needs it to derive.
    spending: CompressedPoint,
}

/// schemeId 3's scanner.
pub type Scanner = HybridScanner<MlKem768Suite>;

impl<S: Suite> core::fmt::Debug for HybridScanner<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scanner")
            .field("ek", &self.ek)
            .field("viewing_pk_ec", &self.viewing_pk_ec)
            .field("spending", &self.spending)
            .field("dk", &"[REDACTED]")
            .field("viewing_ec_seed", &"[REDACTED]")
            .finish()
    }
}

/// Recompute schemeId 3's `ek` from `(d, z)` and require it equal `registered`. §1.
///
/// Both sides are public (registry vs derived).
///
/// # Errors
///
/// [`Error::Malformed`] if `kem_seed` has the wrong length;
/// [`Error::TrackingKeyMismatch`] if the recomputed key differs from `registered`.
pub fn verified_ek(kem_seed: &[u8], registered: &[u8]) -> Result<Vec<u8>, Error> {
    verified_ek_for::<MlKem768>(kem_seed, registered)
}

/// [`verified_ek`] for any KEM.
fn verified_ek_for<K: Kem>(kem_seed: &[u8], registered: &[u8]) -> Result<Vec<u8>, Error> {
    let (ek, _) = K::keygen(kem_seed)?;
    if ek.as_slice() != registered {
        return Err(Error::TrackingKeyMismatch);
    }
    Ok(ek)
}

/// ERC-5564 payload. §3: `epk ‖ ct` in `ephemeralPubKey`, `view_tag` at `metadata[0]`.
#[derive(Debug, Clone)]
pub struct HybridAnnouncement<S> {
    /// Required sender ephemeral point.
    pub epk: CompressedPoint,
    /// KEM ciphertext: 1 088 bytes of ML-KEM-768 on schemeId 3.
    ct: Vec<u8>,
    /// `metadata[0]`. Compared in full.
    pub view_tag: [u8; VIEW_TAG_BYTES],
    /// ERC-5564 `stealthAddress` for this payment. `[0u8; 20]` is a valid Ethereum address,
    /// so it cannot stand in for "missing".
    pub stealth_address: [u8; 20],
    suite: PhantomData<S>,
}

/// schemeId 3's announcement.
pub type Announcement = HybridAnnouncement<MlKem768Suite>;

impl<S: Suite> HybridAnnouncement<S> {
    /// Construct an announcement, checking the ciphertext length.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `ct` is not the suite KEM's `CT_BYTES`.
    pub fn new(
        epk: CompressedPoint,
        ct: Vec<u8>,
        view_tag: [u8; VIEW_TAG_BYTES],
        stealth_address: [u8; 20],
    ) -> Result<Self, Error> {
        if ct.len() != <S::Kem as Kem>::CT_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self {
            epk,
            ct,
            view_tag,
            stealth_address,
            suite: PhantomData,
        })
    }

    /// Ciphertext bytes.
    ///
    /// ```compile_fail
    /// # use pqsa_per_payment::Announcement;
    /// # fn truncate(ann: &mut Announcement) {
    /// ann.ct.pop();
    /// # }
    /// ```
    #[must_use]
    pub fn ct(&self) -> &[u8] {
        &self.ct
    }
}

/// Successful scan. [`StealthScheme::spend_key`] checks that `master` controls `stealth_address`.
#[derive(Clone)]
pub struct Match {
    /// Derived stealth address. §2.4 makes the comparison against the announced
    /// `stealthAddress` a MUST and `match_from_secret` performs it, so a `Match` never
    /// carries an address that disagrees with the announcement it came from.
    pub stealth_address: [u8; 20],
    /// Payment secret for the one-time key.
    pub shared_secret: Zeroizing<Bytes32>,
}

/// Offset and view tag from the payment secret, per §1.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if §1's offset is not a valid scalar (probability about 2⁻¹²⁸).
pub fn derive_from_shared_secret(
    ss: &Bytes32,
) -> Result<(Zeroizing<Bytes32>, [u8; VIEW_TAG_BYTES]), Error> {
    Ok((offset_of(ss)?, view_tag_of(ss)))
}

/// `SHA256(DS_viewtag ‖ ss)[0]`. Does not compute the offset.
#[must_use]
pub fn view_tag_of(ss: &Bytes32) -> [u8; VIEW_TAG_BYTES] {
    let mut h = Sha256::new();
    h.update(DS_VIEWTAG);
    h.update(ss);
    let tag_digest = Zeroizing::new(h.finalize());
    let mut view_tag = [0u8; VIEW_TAG_BYTES];
    view_tag.copy_from_slice(&tag_digest[..VIEW_TAG_BYTES]);
    view_tag
}

/// §1 offset from `ss`. Separate from [`view_tag_of`] so a scanner can reject on the tag
/// before computing the offset.
fn offset_of(ss: &Bytes32) -> Result<Zeroizing<Bytes32>, Error> {
    let mut h = Sha256::new();
    h.update(DS_OFFSET);
    h.update(ss);
    let digest = Zeroizing::new(h.finalize());
    let mut base = Zeroizing::new([0u8; 32]);
    base.copy_from_slice(&digest);
    check_offset(base)
}

/// §1 range check. `base`, read big-endian, is the offset if `0 < base < n`. Otherwise it is
/// [`Error::NoValidScalar`]: nothing is reduced mod `n` and nothing is retried. The sender
/// draws new randomness and a scanner skips (§2.4, §2.5).
fn check_offset(base: Zeroizing<Bytes32>) -> Result<Zeroizing<Bytes32>, Error> {
    pqsa_ec::validate_scalar(&base)?;
    Ok(base)
}

/// SHA3-256(DS ‖ ss_ec ‖ ss_pq ‖ epk ‖ ct ‖ viewing_pk_ec ‖ ek) at schemeId 3's lengths.
/// Direct hash, not HKDF. §1.1.
///
/// `ss_ec` is the 32-byte x-coordinate; other fields are wire/registry encodings.
///
/// # Errors
///
/// [`Error::Malformed`] if `ss_pq`, `ct` or `ek` has the wrong length.
pub fn combine_secrets(
    domain_separator: &[u8],
    ss_ec: &Bytes32,
    ss_pq: &[u8],
    epk: &CompressedPoint,
    ct: &[u8],
    viewing_pk_ec: &CompressedPoint,
    ek: &[u8],
) -> Result<Zeroizing<Bytes32>, Error> {
    combine_for::<MlKem768>(domain_separator, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
}

/// [`combine_secrets`] at KEM `K`'s lengths.
fn combine_for<K: Kem>(
    domain_separator: &[u8],
    ss_ec: &Bytes32,
    ss_pq: &[u8],
    epk: &CompressedPoint,
    ct: &[u8],
    viewing_pk_ec: &CompressedPoint,
    ek: &[u8],
) -> Result<Zeroizing<Bytes32>, Error> {
    if ss_pq.len() != K::SS_BYTES || ct.len() != K::CT_BYTES || ek.len() != K::EK_BYTES {
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
    let digest = Zeroizing::new(h.finalize());
    let mut ss = Zeroizing::new([0u8; 32]);
    ss.copy_from_slice(&digest);
    Ok(ss)
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
        shared_secret: Zeroizing::new(*ss),
    })
}

/// `spending_pk + offset·G`.
fn add_points(spending: &CompressedPoint, offset: &Bytes32) -> Option<CompressedPoint> {
    let offset_point = pqsa_ec::public_point(offset).ok()?;
    pqsa_ec::add_points(spending, &offset_point).ok()
}

/// `epk` and `ct` from an `ephemeralPubKey`, or `None` for any shape §2.7 makes a skip:
/// a length other than the suite's (1 121 on schemeId 3), or an `epk` that is not a valid
/// compressed point.
fn parse_ephemeral_pub_key<S: Suite>(field: &[u8]) -> Option<(CompressedPoint, &[u8])> {
    if field.len() != Hybrid::<S>::EPHEMERAL_PUB_KEY_BYTES {
        return None;
    }
    let (epk, ct) = field.split_at(33);
    Some((pqsa_ec::decode_point(epk).ok()?, ct))
}

/// §2.5 up to `ss`: ECDH, decapsulation with the held key, and the combiner, with the
/// scanner's verified `ek`.
fn payment_secret<S: Suite>(
    scanner: &HybridScanner<S>,
    epk: &CompressedPoint,
    ct: &[u8],
) -> Option<Zeroizing<Bytes32>> {
    let ss_ec = pqsa_ec::ecdh(&scanner.viewing_ec_seed, epk).ok()?;
    let ss_pq = <S::Kem as Kem>::decapsulate_with(&scanner.dk, ct).ok()?;
    combine_for::<S::Kem>(
        S::DOMAIN_SEPARATOR,
        &ss_ec,
        &ss_pq,
        epk,
        ct,
        &scanner.viewing_pk_ec,
        &scanner.ek,
    )
    .ok()
}
/// schemeId 3 combiner domain separator. §2.4.
const DS_HYBRID: &[u8] = b"pq-stealth/hybrid-payment/v1";

/// Draws before [`StealthScheme::announce_random`] gives up. A draw is unusable when `esk` or
/// the offset is out of range, each with probability about 2⁻¹²⁸, so running out means the
/// RNG is broken.
const RANDOM_DRAWS: usize = 64;

/// The rest of §2.4 once `esk` is chosen: ECDH, `encapsulate`, the §1.1 combiner, the address.
/// [`Error::SeedRejected`] if the offset is out of range, so the caller draws again.
fn finish_announcement<S: Suite>(
    meta: &HybridMetaAddress<S>,
    esk: &Bytes32,
    epk: CompressedPoint,
    encapsulate: impl FnOnce(&[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error>,
) -> Result<HybridAnnouncement<S>, Error> {
    let viewing_pk_ec = meta.viewing_ec;
    let ss_ec = pqsa_ec::ecdh(esk, &viewing_pk_ec)?;
    let (ct, ss_pq) = encapsulate(&meta.ek)?;
    let ss = combine_for::<S::Kem>(
        S::DOMAIN_SEPARATOR,
        &ss_ec,
        &ss_pq,
        &epk,
        &ct,
        &viewing_pk_ec,
        &meta.ek,
    )?;
    // An out-of-range offset rejects this announcement's randomness, not the meta-address. §1.
    let (offset, view_tag) = derive_from_shared_secret(&ss).map_err(|e| match e {
        Error::NoValidScalar => Error::SeedRejected,
        other => other,
    })?;
    let stealth = add_points(&meta.spending, &offset).ok_or(Error::Malformed)?;
    HybridAnnouncement::new(epk, ct, view_tag, pqsa_ec::address_of(&stealth))
}

impl<S: Suite> StealthScheme for Hybrid<S> {
    const SCHEME_ID: u64 = S::SCHEME_ID;
    const NAME: &'static str = S::NAME;
    const KEYGEN_SEED_BYTES: usize = 64 + <S::Kem as Kem>::KEYGEN_SEED_BYTES;
    const ANNOUNCE_SEED_BYTES: usize = 32 + <S::Kem as Kem>::ENCAP_SEED_BYTES;

    type Meta = HybridMetaAddress<S>;
    type Master = Master;
    type Tracking = Tracking;
    type Announcement = HybridAnnouncement<S>;
    type Match = Match;
    type Scanner = HybridScanner<S>;
    type SpendKey = SpendKey;

    fn kem_id() -> Vec<u8> {
        <S::Kem as Kem>::id()
    }

    /// `spending_seed(32) ‖ viewing_ec_seed(32) ‖ kem_seed`, `kem_seed` 64 bytes on schemeId 3.
    /// Guard compares the spending seed with each 32-byte component after it: `viewing_ec_seed`,
    /// `d` and `z` on schemeId 3.
    fn keygen(seed: &[u8]) -> Result<(HybridMetaAddress<S>, Master, Tracking), Error> {
        if seed.len() != Self::KEYGEN_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let spending_seed: &Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
        let viewing_ec_seed: &Bytes32 = seed[32..64].try_into().map_err(|_| Error::Malformed)?;
        reject_if_spending_key_is_delegated(spending_seed, &seed[32..])?;
        let spending = pqsa_ec::public_point(spending_seed)?;
        let viewing_ec = pqsa_ec::public_point(viewing_ec_seed)?;
        let (ek, dk_seed) = <S::Kem as Kem>::keygen(&seed[64..])?;
        Ok((
            HybridMetaAddress::new(spending, viewing_ec, ek)?,
            Master {
                spending_seed: Zeroizing::new(*spending_seed),
                viewing_ec_seed: Some(Zeroizing::new(*viewing_ec_seed)),
                kem_seed: dk_seed.clone(),
            },
            Tracking {
                viewing_ec_seed: Some(Zeroizing::new(*viewing_ec_seed)),
                kem_seed: dk_seed,
            },
        ))
    }

    /// §2.4: `esk` and the KEM's encapsulation randomness (`ML-KEM.Encaps(ek)` on schemeId 3)
    /// from the operating system's CSPRNG, both drawn again if `esk` or the offset is out of
    /// range.
    fn announce_random(meta: &HybridMetaAddress<S>) -> Result<HybridAnnouncement<S>, Error> {
        let mut esk = Zeroizing::new([0u8; 32]);
        for _ in 0..RANDOM_DRAWS {
            pqsa_core::os_random(esk.as_mut())?;
            let epk = match pqsa_ec::public_point(&esk) {
                Ok(epk) => epk,
                Err(Error::NoValidScalar) => continue,
                Err(other) => return Err(other),
            };
            match finish_announcement(meta, &esk, epk, <S::Kem as Kem>::encapsulate_random) {
                Err(Error::SeedRejected) => continue,
                other => return other,
            }
        }
        Err(Error::Rng)
    }

    /// `ephemeral_seed(32) ‖ encap_seed`, then the §1.1 combiner. On schemeId 3 `encap_seed`
    /// is ML-KEM's 32-byte `m`, through `Encaps_internal`.
    fn announce(meta: &HybridMetaAddress<S>, seed: &[u8]) -> Result<HybridAnnouncement<S>, Error> {
        if seed.len() != Self::ANNOUNCE_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let esk: &Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
        // Invalid ephemeral scalar is SeedRejected (retry the next index), not NoValidScalar.
        let epk = pqsa_ec::public_point(esk).map_err(|e| match e {
            Error::NoValidScalar => Error::SeedRejected,
            other => other,
        })?;
        finish_announcement(meta, esk, epk, |ek| {
            <S::Kem as Kem>::encapsulate(ek, &seed[32..])
        })
    }

    /// ECDH + decaps + combiner. `epk` and `ct` are fresh per announcement. The long-term
    /// tracking key still decapsulates every past `ct`.
    fn scan(scanner: &HybridScanner<S>, ann: &HybridAnnouncement<S>) -> Option<Match> {
        let ss = payment_secret(scanner, &ann.epk, &ann.ct)?;
        match_from_secret(&ss, &scanner.spending, &ann.view_tag, &ann.stealth_address)
    }

    /// Checks `ek` and the viewing point against the registry, and expands the decapsulation
    /// key once. Either mismatch is [`Error::TrackingKeyMismatch`]; a missing tracking viewing
    /// seed is [`Error::Malformed`].
    fn bind(tracking: &Tracking, meta: &HybridMetaAddress<S>) -> Result<HybridScanner<S>, Error> {
        let viewing_ec_seed = tracking.viewing_ec_seed.as_ref().ok_or(Error::Malformed)?;
        let registered_viewing = meta.viewing_ec;
        let viewing_pk_ec = pqsa_ec::public_point(viewing_ec_seed)?;
        if viewing_pk_ec != registered_viewing {
            return Err(Error::TrackingKeyMismatch);
        }
        Ok(HybridScanner {
            ek: verified_ek_for::<S::Kem>(&tracking.kem_seed, &meta.ek)?,
            dk: <S::Kem as Kem>::decapsulation_key(&tracking.kem_seed)?,
            viewing_pk_ec,
            viewing_ec_seed: viewing_ec_seed.clone(),
            spending: meta.spending,
        })
    }

    fn spend_key(master: &Master, m: &Match) -> Result<SpendKey, Error> {
        spend_key_from(&master.spending_seed, &m.shared_secret, &m.stealth_address)
    }

    fn match_address(m: &Match) -> [u8; 20] {
        m.stealth_address
    }

    fn meta_to_bytes(meta: &HybridMetaAddress<S>) -> Vec<u8> {
        [
            meta.spending.as_bytes().as_slice(),
            meta.viewing_ec.as_bytes(),
            &meta.ek,
        ]
        .concat()
    }

    fn meta_from_bytes(bytes: &[u8]) -> Option<HybridMetaAddress<S>> {
        if bytes.len() != Self::META_ADDRESS_BYTES {
            return None;
        }
        HybridMetaAddress::new(
            pqsa_ec::decode_point(&bytes[..33]).ok()?,
            pqsa_ec::decode_point(&bytes[33..66]).ok()?,
            bytes[66..].to_vec(),
        )
        .ok()
    }

    /// `ephemeralPubKey` = `epk ‖ ct`, `metadata` = `view_tag`.
    ///
    /// `metadata` is the view tag alone. ERC-5564 lets the bytes after it carry token data;
    /// that is the caller's to append, since this scheme does not know the token or amount.
    fn announcement_to_bytes(ann: &HybridAnnouncement<S>) -> ([u8; 20], Vec<u8>, Vec<u8>) {
        (
            ann.stealth_address,
            [ann.epk.as_bytes().as_slice(), &ann.ct].concat(),
            ann.view_tag.to_vec(),
        )
    }

    /// Reads the view tag from `metadata[0]` and ignores any later bytes, which ERC-5564
    /// leaves to the sender.
    fn announcement_from_bytes(
        stealth_address: &[u8; 20],
        ephemeral_pub_key: &[u8],
        metadata: &[u8],
    ) -> Option<HybridAnnouncement<S>> {
        if metadata.len() < VIEW_TAG_BYTES {
            return None;
        }
        let (epk, ct) = parse_ephemeral_pub_key::<S>(ephemeral_pub_key)?;
        HybridAnnouncement::new(
            epk,
            ct.to_vec(),
            metadata[..VIEW_TAG_BYTES].try_into().ok()?,
            *stealth_address,
        )
        .ok()
    }
}

impl<S: Suite> ExportableSpendKey for Hybrid<S> {
    fn spend_key_bytes(k: &SpendKey) -> &[u8] {
        k.expose_secret()
    }
}

/// `stealth_sk = spending_sk + H(ss) mod n`. §2.6.
///
/// Returns [`Error::MasterKeyMismatch`] if that key does not control `stealth_address`.
/// One-time key + `ss` recovers the master; do not disclose both.
fn spend_key_from(
    spending_seed: &Bytes32,
    shared_secret: &Bytes32,
    stealth_address: &[u8; 20],
) -> Result<SpendKey, Error> {
    let offset = offset_of(shared_secret)?;
    let stealth_sk = pqsa_ec::add_scalars(spending_seed, &offset)?;
    let stealth_pk = pqsa_ec::public_point(&stealth_sk)?;
    if pqsa_ec::address_of(&stealth_pk) != *stealth_address {
        return Err(Error::MasterKeyMismatch);
    }
    let mut key = SpendKey::default();
    key.expose_secret_mut().copy_from_slice(stealth_sk.as_ref());
    Ok(key)
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
redacted_debug!(Match, secrets: [shared_secret], shown: [stealth_address]);

pub mod erc5564;

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

    #[test]
    fn secret_fields_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let ann = SchemeId3::announce(&meta, &[0x33; 64]).unwrap();
        let matched = SchemeId3::scan(&scanner, &ann).unwrap();
        assert_zeroize_on_drop(&master.spending_seed);
        assert_zeroize_on_drop(&master.viewing_ec_seed);
        assert_zeroize_on_drop(&master.kem_seed);
        assert_zeroize_on_drop(&tracking.viewing_ec_seed);
        assert_zeroize_on_drop(&tracking.kem_seed);
        assert_zeroize_on_drop(&scanner.viewing_ec_seed);
        assert_zeroize_on_drop(&scanner.dk);
        assert_zeroize_on_drop(&matched.shared_secret);
        assert_zeroize_on_drop(&derive_from_shared_secret(&matched.shared_secret).unwrap().0);
        assert_zeroize_on_drop(&payment_secret(&scanner, &ann.epk, &ann.ct).unwrap());
        assert_zeroize_on_drop(&SchemeId3::spend_key(&master, &matched).unwrap());
    }

    #[test]
    fn spend_key_redacts_debug_and_zeroizes() {
        use zeroize::Zeroize;
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let ann = SchemeId3::announce(&meta, &[0x33; 64]).unwrap();
        let matched = SchemeId3::scan(&scanner, &ann).unwrap();
        let mut key = SchemeId3::spend_key(&master, &matched).unwrap();
        let bytes = SchemeId3::spend_key_bytes(&key);
        assert!(bytes.iter().any(|&b| b != 0));
        assert_eq!(
            pqsa_ec::address_of(&pqsa_ec::public_point(key.expose_secret()).unwrap()),
            ann.stealth_address
        );
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&hex::encode(bytes)));
        assert!(!debug.contains(&format!("{:?}", bytes)));
        key.zeroize();
        assert_eq!(SchemeId3::spend_key_bytes(&key), &[0u8; 32]);
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
        let wrong = {
            let mut b = mixed.viewing_ec_seed.as_ref().unwrap().clone();
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
    /// The §2.4 sender: a random announcement is found and spent by its recipient, and two
    /// of them share nothing a scanner or an observer could link.
    #[test]
    fn a_random_announcement_round_trips_and_is_fresh() {
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let a = SchemeId3::announce_random(&meta).unwrap();
        let b = SchemeId3::announce_random(&meta).unwrap();
        for ann in [&a, &b] {
            let m = SchemeId3::scan(&scanner, ann).expect("our own announcement must match");
            assert_eq!(m.stealth_address, ann.stealth_address);
            assert!(SchemeId3::spend_key(&master, &m).is_ok());
        }
        assert_ne!(a.epk, b.epk, "a repeated epk links two announcements");
        assert_ne!(a.ct, b.ct, "a repeated ct means a repeated m");
        assert_ne!(a.stealth_address, b.stealth_address);
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
            hex(SchemeId3::spend_key_bytes(&sk)),
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
        assert_eq!(
            SchemeId3::spend_key(&same_spending, &m)
                .unwrap()
                .expose_secret(),
            sk.expose_secret()
        );
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

        let epk = modified.epk;
        let viewing_seed = tracking.viewing_ec_seed.expect("schemeId 3 tracking key");
        let viewing_pk = meta.viewing_ec;
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
        let mut sender = pqsa_core::SenderState::resume(&[0x5a; 32], 0);
        let ann = SchemeId3::announce(&meta, &sender.draw_seed::<SchemeId3>().unwrap()).unwrap();
        let (addr, epk, metadata) = SchemeId3::announcement_to_bytes(&ann);
        assert_eq!(epk.len(), 33 + MlKem768::CT_BYTES);
        assert_eq!(metadata.len(), VIEW_TAG_BYTES);

        let blob: Vec<u8> = addr.iter().chain(&epk).chain(&metadata).copied().collect();
        let digest: String = Sha256::digest(&blob)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            "b41b33fe1bfd55b23f7704ff9ee15d991ec1d5dd6a0d261752f4485068abc5ef"
        );
    }
}
