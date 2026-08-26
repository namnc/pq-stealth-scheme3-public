//! schemeIds 2 and 3: one ML-KEM announcement per payment, and no per-counterparty state
//! on either side (§5's sender-wide seed state is every rung's, this pair included).
//!
//! Specification: §2, which depends on §1, §5, §6, §7, §8 and §9. It also depends on the
//! SEC1 decoder — the `0x02`/`0x03`-only tag rule and its rationale — which is why
//! `pqsa-ec::decode_point` is a dependency rather than a local function. **Where that rule is
//! stated depends on the tree**: §3 in a set specifying the pairwise-channel rung, §2.2 in a
//! document specifying this rung alone. It is the same rule and the same decoder.
//!
//! **Cited by section number and not by document.** One numbering runs across every document
//! that specifies a rung of this ladder, so each reference above resolves in whichever of them
//! a reader holds, including a tree that carries only one.
//!
//! **And deliberately not a URL either.** The specification ships in the same tree as this
//! crate, so a reader already has it; a link to a hosting account is the one form of this
//! reference that can rot, and the one this header carried named the working repository
//! rather than the published one — a reader following it would have reached either nothing
//! or a history the release exists to not publish.
//!
//! # The two rungs, and what separates them
//!
//! | | payment secret | keygen seed | meta-address | announcement |
//! |---|---|---|---|---|
//! | [`SchemeId2`] | the KEM secret directly | 96 B | 1 217 B | 1 096 B |
//! | [`SchemeId3`] | the KEM secret **combined with an ECDH secret** | 128 B | 1 250 B | 1 129 B |
//!

//!
//! §2.9 says everything in §2.1–§2.8 applies to schemeId 3 unchanged but for four items, that
//! from `ss` onward the two are identical, and — the clause that shapes this crate — that **an
//! implementation MUST share that code rather than duplicate it.** So the two types below are
//! thin: [`derive_from_shared_secret`] is where the shared half lives, and it is public so a
//! reader can see there is exactly one of it.
//!
//! # What schemeId 3's EC half is for, stated here because it is misread
//!
//! **It is not post-quantum protection.** Spending is secp256k1 ECDSA in both rungs, so a
//! CRQC ends both whatever the announcement layer does. The EC half covers the interval before
//! that, against a failure of an ML-KEM *implementation*. §9 says implementations MUST NOT
//! present it otherwise, and this paragraph is that requirement discharged in the API docs.
//!
//! # Status
//!
//! **Both rungs are implemented HERE**, against the committed conformance vectors.
//! schemeId 2 additionally has an older *upstream* implementation that derives a different
//! payment secret than this specification, and schemeId 3 has no upstream implementation.
//!
use pqsa_core::{
    Bytes32, Error, ExportableSpendKey, StealthScheme, VIEW_TAG_BYTES,
    reject_if_spending_key_is_delegated,
};
use pqsa_ec::CompressedPoint;
use pqsa_kem::{Kem, MlKem768};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

/// §1's domain separator for the offset. The FIRST input to the hash, never appended.
const DS_OFFSET: &[u8] = b"pq-stealth/offset/v1";

/// §1's domain separator for the view tag. A **separate digest** from the offset's — taking a
/// slice of `H(ss)` instead is one of the wrong answers V1-07 names.
const DS_VIEWTAG: &[u8] = b"pq-stealth/view-tag/v1";

/// schemeId 2: the payment secret is the KEM shared secret, taken directly.
///
/// The rung that needs nothing: no protocol change, no new contract, and no account that can
/// batch two calls. §2.1–§2.8.
pub struct SchemeId2;

/// schemeId 3: the payment secret combines an ECDH secret with the KEM secret.
///
/// A migration hedge against an ML-KEM implementation defect, to be retired at the NIST date
/// — see this crate's own note on what the EC half is for, and §9. §2.9.
pub struct SchemeId3;

/// What a recipient publishes: the spending point, optionally a viewing point, and the KEM
/// encapsulation key.
///
/// §6's registry column fixes the concatenation order, and for schemeId 3 the ORDER is
/// where the older external implementations diverge from this document.
#[derive(Debug, Clone)]
pub struct MetaAddress {
    /// The point payments are derived against. Never used to scan.
    pub spending: CompressedPoint,
    /// schemeId 3 only: the point the sender's ECDH half is computed against.
    pub viewing_ec: Option<CompressedPoint>,
    /// The ML-KEM-768 encapsulation key, 1 184 bytes.
    pub ek: Vec<u8>,
}

/// What a recipient keeps. Never leaves the device, and never delegated.
#[derive(Clone)]
pub struct Master {
    /// The scalar every one-time key is offset from.
    pub spending_seed: Bytes32,
    /// schemeId 3 only.
    pub viewing_ec_seed: Option<Bytes32>,
    /// ML-KEM's `(d, z)` seed pair, 64 bytes — not the expanded key.
    pub kem_seed: Vec<u8>,
}

/// What a recipient MAY hand to a scanning service.
///
/// §2.1 permits delegating this and only this. §9 records the cost: a delegated scanner learns
/// the recipient's entire payment graph, and combined with a quantum adversary it takes
/// everything. Both are the recipient's decision and neither is a defect.
#[derive(Clone)]
pub struct Tracking {
    /// schemeId 3 only.
    pub viewing_ec_seed: Option<Bytes32>,
    /// ML-KEM's seed pair.
    pub kem_seed: Vec<u8>,
}

/// A tracking key that has been **checked against a meta-address** — every delegated
/// component against its registered counterpart — plus the values scanning
/// would otherwise recompute per announcement.
///
/// Only [`StealthScheme::bind`] builds one, and [`StealthScheme::scan`] takes nothing else. That
/// is deliberate: §1 requires the `ek` recomputed from `(d, z)` be compared against the
/// registry at least once before scanning, AND (schemeId 3) the derived viewing point
/// against the registered one — a check a caller is asked to remember is a check
/// that gets forgotten, and here forgetting either does not compile.
///
/// # What is cached, and why each field is here rather than derived per event
///
/// `ek` is the *verified* encapsulation key — the recomputed one, confirmed equal to the
/// registered one, so a caller can never accidentally bind the registry's copy into a
/// derivation while decapsulating with a different key. `viewing_pk_ec` is schemeId 3's viewing
/// point, which the hybrid combiner takes as an input on every announcement and which is a
/// scalar multiplication to produce. `spending` comes from the meta-address because §2.5 needs
/// it to derive the address and §2.1 forbids delegating it.
///
/// Deriving `ek` inside `scan` would be a full ML-KEM key generation per event,
/// paid on foreign announcements too, so a stranger sets a scanner's workload. §2's cost floor
/// is one decapsulation plus one scalar multiplication per announcement, and that is a floor
/// the specification states rather than an efficiency note.
#[derive(Clone)]
pub struct Scanner {
    /// The delegated `(d, z)` pair. Decapsulation's input.
    kem_seed: Vec<u8>,
    /// schemeId 3 only.
    viewing_ec_seed: Option<Bytes32>,
    /// The encapsulation key **recomputed from `kem_seed` and verified** against the registry.
    ek: Vec<u8>,
    /// schemeId 3 only: the viewing point, derived once.
    viewing_pk_ec: Option<CompressedPoint>,
    /// The registry's spending point. Not delegated material; §2.5 needs it to derive.
    spending: CompressedPoint,
}

/// The `ek` comparison §1 makes a MUST, shared by both rungs because it is one requirement.
///
/// **Constant-time comparison is NOT claimed here and would be misplaced.** Both values are
/// public: one is in a public registry and the other is derived from a key the caller holds. The
/// secret in this operation is `kem_seed`, and it is not what is being compared.
///
/// Public since wave 3 for the same §2.9 reason it exists at all: schemeId 6's tracking key
/// is also an ML-KEM `(d, z)` seed and §1's sentence covers that rung's `bind` too, so a
/// private copy over there would be the duplication this function was written to prevent.
pub fn verified_ek(kem_seed: &[u8], registered: &[u8]) -> Result<Vec<u8>, Error> {
    let (ek, _) = MlKem768::keygen(kem_seed)?;
    if ek.as_slice() != registered {
        return Err(Error::TrackingKeyMismatch);
    }
    Ok(ek)
}

/// One announcement: the ERC-5564 payload.
///
/// §6's wire table: for schemeId 2 `ephemeralPubKey` is the ciphertext and `metadata` is the
/// **8-byte** view tag; for schemeId 3 `ephemeralPubKey` is the sender's EC point and `metadata`
/// is `view_tag ‖ ct`. The view tag is `metadata[0..8]` in every announcement in the ladder.
///
/// The width matters: a reader who takes the tag as one byte reads seven bytes of
/// ciphertext as tag on schemeId 2 and matches nothing, for ever, with no error anywhere.
#[derive(Debug, Clone)]
pub struct Announcement {
    /// schemeId 3 only: the sender's ephemeral EC point.
    pub epk: Option<CompressedPoint>,
    /// The ML-KEM ciphertext, 1 088 bytes.
    pub ct: Vec<u8>,
    /// The first eight bytes of `metadata`, and an EXACT matcher at 2⁻⁶⁴ — not a prefilter.
    pub view_tag: [u8; VIEW_TAG_BYTES],
    /// ERC-5564's `stealthAddress` argument: the address this announcement's payment derives.
    ///
    /// §2.4 requires it be exactly that address, and a sender that announces one and pays
    /// another has made a payment its recipient cannot find. Carried here rather than
    /// recomputed at serialisation time, because recomputing it needs `ss`.
    ///
    /// **Always the announced address**, whether this announcement was built or parsed.
    ///
    /// > **Never a sentinel.** A parser that took only the two payload fields would leave
    /// > every parsed announcement carrying twenty zero bytes here, and a caller implementing
    /// > §2.8's comparison against such an announcement would reject every
    /// > valid payment. The address is ERC-5564's second `announce()` argument and a scanner
    /// > reading a log has it — the parser just did not ask, and the sentinel made a gap in
    /// > this API look like a property of the event.
    pub stealth_address: [u8; 20],
}

/// A matched announcement, with what spending needs.
#[derive(Clone)]
pub struct Match {
    /// The derived stealth address. Compare against the announced one only as a MAY — §2.8
    /// records why it is not a MUST, and it is a privacy trade rather than an oversight.
    pub stealth_address: [u8; 20],
    /// The payment secret, needed to derive the one-time key.
    pub shared_secret: Bytes32,
}

/// The half schemeIds 2 and 3 share, and the reason this crate holds both.
///
/// From `ss` onward the two rungs are byte-identical: the offset, the view tag, the address,
/// the scanner order and the error/skip table. §2.9 requires that code be shared rather than
/// duplicated, so it is one public function and a reader can confirm there is one.
///
/// Returns `(offset, view_tag)`. The offset is a one-time pad over the full scalar field,
/// which is the property §9's "a leaked one-time key alone yields nothing" rests on.
///
/// # Errors
///
/// [`Error::NoValidScalar`] if the reduction yields no valid scalar within §1's counter bound
/// — and §1 requires the bound be a failure rather than an unbounded retry: `counter = 0`
/// contributes no counter byte, `1..=256` contribute all 256 distinct byte values, so a 257th
/// iteration would re-derive a candidate already rejected.
pub fn derive_from_shared_secret(ss: &Bytes32) -> Result<(Bytes32, [u8; VIEW_TAG_BYTES]), Error> {
    let base: Bytes32 = Sha256::digest([DS_OFFSET, ss.as_slice()].concat()).into();
    let offset = reduce_to_scalar(&base)?;
    Ok((offset, view_tag_of(ss)))
}

/// §1's view tag ALONE: `SHA256(DS_viewtag ‖ ss)[0..8]`, one hash, no offset.
///
/// Public because the channel rungs' scanner needs exactly this and nothing more, per
/// counter, per window — §3.6 prices the lookahead window at two SHA-256 calls per counter
/// (the payment secret, then this), and deriving the tag through
/// [`derive_from_shared_secret`] pays the offset's scalar-validity check as well, which is
/// an EC scalar multiplication the window never uses. Measured before it was believed:
/// the difference is the whole window cost, about a thousandfold per counter.
#[must_use]
pub fn view_tag_of(ss: &Bytes32) -> [u8; VIEW_TAG_BYTES] {
    let tag_digest = Sha256::digest([DS_VIEWTAG, ss.as_slice()].concat());
    let mut view_tag = [0u8; VIEW_TAG_BYTES];
    view_tag.copy_from_slice(&tag_digest[..VIEW_TAG_BYTES]);
    view_tag
}

/// §1's counter-based scalar reduction, given in full because the two sides MUST agree.
///
/// ```text
/// base = SHA256(DS_offset || ss)
/// for counter in 0, 1, 2, ... 256:
///     candidate = base                                    if counter == 0
///               = SHA256(DS_offset || base || u8(counter))  otherwise
///     if 0 < candidate < n:  stop
/// fail
/// ```
///
/// **Every digest is a big-endian 256-bit integer**, and it has to be said:
/// a little-endian read gives a different scalar, a different address, and funds the recipient
/// cannot spend. `pqsa_ec` enforces the big-endian read, so this function only has to not
/// reduce — it hands each candidate to `pqsa_ec` and lets the range check reject it.
///
/// **The bound is exhaustion, not overflow.** `counter = 0` contributes no counter byte and
/// `1..=256` contribute all 256 distinct byte values, so the loop tries 257 distinct inputs and
/// none is repeated; a 257th would re-derive the candidate `counter = 1` already rejected.
/// "Where the byte would wrap" is NOT the justification — that would be the wrong reason
/// for a right rule.
fn reduce_to_scalar(base: &Bytes32) -> Result<Bytes32, Error> {
    for counter in 0u16..=256 {
        let candidate: Bytes32 = if counter == 0 {
            *base
        } else {
            #[allow(clippy::cast_possible_truncation)]
            let byte = counter as u8;
            Sha256::digest([DS_OFFSET, base.as_slice(), &[byte]].concat()).into()
        };
        // The range check IS the acceptance test: `pqsa_ec` rejects zero and anything at or
        // above the group order rather than reducing it, per §1.
        if pqsa_ec::public_point(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(Error::NoValidScalar)
}

/// §1.1's hybrid combiner, and the caller supplies the separator and names the output.
///
/// ```text
/// hybrid_combine(DS, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
///     = SHA3-256(DS || ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek)
/// ```
///
/// **A direct SHA3-256 hash, not HKDF**, and the separator is the FIRST input — neither
/// appended nor length-prefixed. Every field is the bytes as they appear on the wire or in the
/// registry, at the lengths §6 gives: `epk` and `viewing_pk_ec` are 33-byte compressed points,
/// `ct` is 1 088 announcement bytes, `ek` is 1 184 registry bytes, and `ss_ec` is the 32-byte
/// x-coordinate — the one field that is not a wire encoding.
///
/// # Errors
///
/// [`Error::Malformed`] on a wrong-length `ct` or `ek`.
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

/// The shared scanner tail: from `ss` to a [`Match`], or `None`.
///
/// One function for both rungs, because §2.9 requires the code be shared rather than
/// duplicated and a reader should be able to confirm there is one of it. **The view-tag
/// comparison is over all eight bytes** — §1's width — and a mismatch is "not ours", never an
/// error.
fn match_from_secret(
    ss: &Bytes32,
    spending: &CompressedPoint,
    announced: &[u8; VIEW_TAG_BYTES],
) -> Option<Match> {
    let (offset, view_tag) = derive_from_shared_secret(ss).ok()?;
    if &view_tag != announced {
        return None;
    }
    let stealth = add_points(spending, &offset)?;
    Some(Match {
        stealth_address: pqsa_ec::address_of(&stealth),
        shared_secret: *ss,
    })
}

/// `spending_pk + offset·G`, the sender's and scanner's side of §2.3's derivation.
///
/// The recipient's side is `spending_sk + offset` mod n, in [`pqsa_ec::add_scalars`]. The two
/// MUST give one point, and `pqsa-ec`'s own test asserts that identity — it is what makes a
/// sender's address and a recipient's key the same address.
fn add_points(spending: &CompressedPoint, offset: &Bytes32) -> Option<CompressedPoint> {
    let offset_point = pqsa_ec::public_point(offset).ok()?;
    pqsa_ec::add_points(spending, &offset_point).ok()
}

impl StealthScheme for SchemeId2 {
    const SCHEME_ID: u64 = 2;
    const NAME: &'static str = "schemeId 2 (direct KEM)";
    const KEYGEN_SEED_BYTES: usize = 96;
    const ANNOUNCE_SEED_BYTES: usize = 32;

    type Meta = MetaAddress;
    type Master = Master;
    type Tracking = Tracking;
    type Announcement = Announcement;
    type Match = Match;
    type Scanner = Scanner;
    type SpendKey = Bytes32;

    /// `spending_seed(32) ‖ kem_seed(64)`, and the delegation guard runs over `kem_seed` alone
    /// — 33 window offsets, which is complete because there is one delegated secret.
    fn keygen(seed: &[u8]) -> Result<(MetaAddress, Master, Tracking), Error> {
        if seed.len() != Self::KEYGEN_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let spending_seed: Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
        let kem_seed = seed[32..].to_vec();
        reject_if_spending_key_is_delegated(&spending_seed, &kem_seed)?;
        let spending = pqsa_ec::public_point(&spending_seed)?;
        let (ek, dk_seed) = MlKem768::keygen(&kem_seed)?;
        Ok((
            MetaAddress {
                spending,
                viewing_ec: None,
                ek,
            },
            Master {
                spending_seed,
                viewing_ec_seed: None,
                kem_seed: dk_seed.clone(),
            },
            Tracking {
                viewing_ec_seed: None,
                kem_seed: dk_seed,
            },
        ))
    }

    /// `(ct, ss) = Encaps(ek, m)` with `m` the whole announce seed, then §2.4's derivation.
    ///
    /// **`ss` is the KEM secret taken directly** — that is what makes this the "direct KEM"
    /// rung, and it is the one line schemeId 3 replaces.
    fn announce(meta: &MetaAddress, seed: &[u8]) -> Result<Announcement, Error> {
        if seed.len() != Self::ANNOUNCE_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let (ct, ss) = MlKem768::encapsulate(&meta.ek, seed)?;
        let (offset, view_tag) = derive_from_shared_secret(&ss)?;
        let stealth = add_points(&meta.spending, &offset).ok_or(Error::Malformed)?;
        Ok(Announcement {
            epk: None,
            ct,
            view_tag,
            stealth_address: pqsa_ec::address_of(&stealth),
        })
    }

    /// One decapsulation per announcement, then the eight-byte tag.
    ///
    /// **There is no prefilter ahead of the KEM**, and §2.5 states that as a cost floor rather
    /// than an implementation choice: the tag is a function of `ss`, so it cannot be computed
    /// before the decapsulation it would have saved. Every negative outcome is `None`.
    fn scan(scanner: &Scanner, ann: &Announcement) -> Option<Match> {
        if ann.epk.is_some() {
            return None;
        }
        let ss = MlKem768::decapsulate(&scanner.kem_seed, &ann.ct).ok()?;
        match_from_secret(&ss, &scanner.spending, &ann.view_tag)
    }

    /// §1's `ek` check, and this rung caches nothing else — it has no viewing point and its
    /// combiner is the KEM secret alone.
    fn bind(tracking: &Tracking, meta: &MetaAddress) -> Result<Scanner, Error> {
        // BOTH sides' shapes are this rung's, not just the tracking object's: a schemeId 3
        // meta-address (registered viewing point present) offered to this rung's bind is
        // cross-rung material even when its spending and KEM halves happen to verify.
        if tracking.viewing_ec_seed.is_some() || meta.viewing_ec.is_some() {
            return Err(Error::Malformed);
        }
        Ok(Scanner {
            ek: verified_ek(&tracking.kem_seed, &meta.ek)?,
            kem_seed: tracking.kem_seed.clone(),
            viewing_ec_seed: None,
            viewing_pk_ec: None,
            spending: meta.spending,
        })
    }

    fn spend_key(master: &Master, m: &Match) -> Result<Bytes32, Error> {
        spend_key_from(master, m)
    }

    fn match_address(m: &Match) -> [u8; 20] {
        m.stealth_address
    }

    fn meta_to_bytes(meta: &MetaAddress) -> Vec<u8> {
        [meta.spending.as_bytes().as_slice(), &meta.ek].concat()
    }

    fn meta_from_bytes(bytes: &[u8]) -> Option<MetaAddress> {
        if bytes.len() != 33 + MlKem768::EK_BYTES {
            return None;
        }
        Some(MetaAddress {
            spending: pqsa_ec::decode_point(&bytes[..33]).ok()?,
            viewing_ec: None,
            ek: bytes[33..].to_vec(),
        })
    }

    /// `ct` in `ephemeralPubKey`, the eight-byte tag in `metadata`. §6's wire table.
    ///
    /// Note the asymmetry with schemeId 3, which is deliberate and which §6 records: this rung
    /// has no genuine ephemeral public key, so the field carries the ciphertext instead. **No
    /// `schemeId` is identifiable by where 1 088 bytes sit**, which is why recognition is by
    /// `schemeId` plus the two field lengths.
    fn announcement_to_bytes(ann: &Announcement) -> ([u8; 20], Vec<u8>, Vec<u8>) {
        (ann.stealth_address, ann.ct.clone(), ann.view_tag.to_vec())
    }

    fn announcement_from_bytes(
        stealth_address: &[u8; 20],
        epk: &[u8],
        metadata: &[u8],
    ) -> Option<Announcement> {
        if epk.len() != MlKem768::CT_BYTES || metadata.len() != VIEW_TAG_BYTES {
            return None;
        }
        Some(Announcement {
            epk: None,
            ct: epk.to_vec(),
            view_tag: metadata.try_into().ok()?,
            stealth_address: *stealth_address,
        })
    }
}

/// The classical spend path: the scalar goes to an ordinary ECDSA signer,
/// so exporting it IS the spend (unlike schemeId 6, which refuses this trait).
impl ExportableSpendKey for SchemeId2 {
    fn spend_key_bytes(k: &Bytes32) -> &[u8] {
        k.as_slice()
    }
}

/// schemeId 3's domain separator, per §2.9. MUST differ from §3.12's and §3.3's.
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

    /// `spending_seed(32) ‖ viewing_ec_seed(32) ‖ kem_seed(64)`.
    ///
    /// **The delegation guard runs over the 96-byte CONCATENATION**, not over each half: 65
    /// window offsets, of which a per-half scan reaches 34. The 31 straddling positions pass a
    /// per-half check while placing the spending seed verbatim in the bytes handed to a scanning
    /// service, and §2.1 records that reproduced end to end against a real payment.
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

    /// `ephemeral_seed(32) ‖ encap_seed(32)`, then §1.1's combiner over all six IKM fields.
    fn announce(meta: &MetaAddress, seed: &[u8]) -> Result<Announcement, Error> {
        if seed.len() != Self::ANNOUNCE_SEED_BYTES {
            return Err(Error::Malformed);
        }
        let viewing_pk_ec = meta.viewing_ec.ok_or(Error::Malformed)?;
        let esk: Bytes32 = seed[..32].try_into().map_err(|_| Error::Malformed)?;
        // §5's rejection rule, and the ONE place in wave 1 where it is reachable: the ephemeral
        // half of the announce seed must be a valid secp256k1 scalar. `Error::SeedRejected`
        // rather than `NoValidScalar` because a caller has to be able to tell "draw the next
        // index" from "this meta-address will never work" -- see that variant's documentation.
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

    /// One decapsulation **and one scalar multiplication** per announcement, so §2.5's cost
    /// floor rises. What it keeps is per-payment forward secrecy: `epk` and `ct` are both fresh.
    ///
    /// **The floor is what it is because of what moved to [`Self::bind`].** `viewing_pk_ec` and
    /// `ek` are both combiner inputs and neither depends on the announcement, so both are
    /// derived once. Deriving them here would add a scalar
    /// multiplication and a full ML-KEM key generation to every event a scanner looked at,
    /// foreign ones included, which lets a stranger set a scanner's workload and overruns the
    /// floor §2.5 states.
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
        match_from_secret(&ss, &scanner.spending, &ann.view_tag)
    }

    /// §1's `ek` check, plus the viewing point — which §1.1 names as the one place an
    /// implementer chooses an encoding rather than copying one, so a divergence here produces
    /// an address the recipient never derives.
    fn bind(tracking: &Tracking, meta: &MetaAddress) -> Result<Scanner, Error> {
        let viewing_ec_seed = tracking.viewing_ec_seed.ok_or(Error::Malformed)?;
        let Some(registered_viewing) = meta.viewing_ec else {
            return Err(Error::Malformed);
        };
        // BOTH delegated secrets are checked against the registry, not just the KEM half.
        // The tracking object is two secrets here, and a viewing seed that derives a point
        // other than the registered one binds a scanner that silently matches NOTHING —
        // every genuine announcement computes ECDH against the registered point, this
        // scanner against an unrelated one, and no error surfaces anywhere downstream.
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
            // BOTH points are validated, not only the spending one: the viewing key is what a
            // sender does ECDH against, so an unvalidated one is an announcement nobody can
            // open. §2.9 requires it and V3-03 pins it.
            viewing_ec: Some(pqsa_ec::decode_point(&bytes[33..66]).ok()?),
            ek: bytes[66..].to_vec(),
        })
    }

    /// `epk` in `ephemeralPubKey`, `view_tag ‖ ct` in `metadata`.
    ///
    /// **The view tag comes FIRST**, and that is the whole of §6's field-order rule: §2.5's
    /// scanner block reads `metadata[0..8]`, so under the superseded `ct ‖ view_tag` layout a
    /// literal implementer would compare their tag against the leading bytes of an ML-KEM
    /// ciphertext — and at eight bytes that matches nothing, so the scanner reports a clean
    /// empty scan rather than the 1-in-256 symptom the one-byte width left.
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

/// The classical spend path: the scalar goes to an ordinary ECDSA signer,
/// so exporting it IS the spend (unlike schemeId 6, which refuses this trait).
impl ExportableSpendKey for SchemeId3 {
    fn spend_key_bytes(k: &Bytes32) -> &[u8] {
        k.as_slice()
    }
}

/// `stealth_sk = (spending_sk + H(ss)) mod n`. §2.6.
///
/// **The hazard §2.6 names: a one-time key together with its `ss` recovers the master.** Given
/// both, `spending_sk = stealth_sk - H(ss)`, so an implementation MUST NOT disclose both for one
/// payment — and this function returning the one-time key is exactly the disclosure boundary.
fn spend_key_from(master: &Master, m: &Match) -> Result<Bytes32, Error> {
    let base: Bytes32 = Sha256::digest([DS_OFFSET, m.shared_secret.as_slice()].concat()).into();
    let offset = reduce_to_scalar(&base)?;
    pqsa_ec::add_scalars(&master.spending_seed, &offset)
}

/// Redacted `Debug` for the secret-bearing types, exactly as `pqsa-channel`'s: a derived
/// impl is a logging surface — `dbg!` or `tracing::debug!(?x)` would emit seeds and payment
/// secrets in clear (decimal byte lists leak as thoroughly as hex). Non-secret fields print;
/// every secret prints as `[REDACTED]`. `MetaAddress` and `Announcement` keep derived
/// `Debug`: their bytes are public by construction. **This crate's own
/// `redaction_leaks_no_secret` covers these types**, so the guarantee is checked in a tree
/// carrying this crate alone; where a sibling crate is also present, its test of the same name
/// additionally covers both crates' types from one place.
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
mod tests {
    use super::*;

    /// `V2-01`'s keygen seed. A real one, so the keypair below is a real keypair.
    const SEED96: &str = "1111111111111111111111111111111111111111111111111111111111111111\
                          e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0\
                          1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// A 128-byte schemeId 3 seed: the 96 above with a viewing scalar spliced in at §2.9's
    /// position. Counted rather than constant-filled, because a repeated byte pattern makes the
    /// delegation guard's window scan fire and the failure then reads as a length error --
    /// which happened once already and cost an afternoon.
    fn seed128() -> Vec<u8> {
        let s = unhex(SEED96);
        let mut out = s[..32].to_vec();
        out.extend((0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)));
        out.extend_from_slice(&s[32..]);
        assert_eq!(out.len(), 128);
        out
    }

    /// **The test the whole `bind` change exists for.**
    ///
    /// §1 says that without the `ek` comparison there is no mechanism by which a corrupt
    /// tracking key surfaces. This asserts both halves of that sentence: the corruption is
    /// invisible to everything else, and the comparison catches it.
    #[test]
    fn a_bit_flipped_tracking_seed_is_caught_by_bind_and_by_nothing_else() {
        let (meta, _master, tracking) = SchemeId2::keygen(&unhex(SEED96)).unwrap();

        let mut corrupt = tracking.clone();
        corrupt.kem_seed[7] ^= 0x01; // one bit, in the `d` half

        // FIRST: the corruption is undetectable locally. This is the half that makes the check
        // necessary rather than merely prudent -- a bit-flipped (d, z) expands through
        // KeyGen_internal into a self-consistent keypair for a DIFFERENT key, so FIPS 203's own
        // dk check passes and there is nothing to notice.
        let (good_ek, _) = MlKem768::keygen(&tracking.kem_seed).unwrap();
        let (bad_ek, _) = MlKem768::keygen(&corrupt.kem_seed).unwrap();
        assert_eq!(
            good_ek.len(),
            bad_ek.len(),
            "both expand to a well-formed key"
        );
        assert_ne!(
            good_ek, bad_ek,
            "to a DIFFERENT key, which is the whole problem"
        );

        // SECOND: bind is what notices, and it reports the right thing.
        assert!(SchemeId2::bind(&tracking, &meta).is_ok());
        assert!(matches!(
            SchemeId2::bind(&corrupt, &meta),
            Err(Error::TrackingKeyMismatch)
        ));
    }

    /// The same, for the rung whose scan has two secrets rather than one -- corrupting `d`.
    #[test]
    fn schemeid3_bind_catches_a_corrupt_kem_seed_too() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        assert!(SchemeId3::bind(&tracking, &meta).is_ok());

        let mut corrupt = tracking.clone();
        corrupt.kem_seed[3] ^= 0x40; // in the `d` half, which is what `ek` depends on
        assert!(matches!(
            SchemeId3::bind(&corrupt, &meta),
            Err(Error::TrackingKeyMismatch)
        ));
    }

    /// **And the VIEWING half is checked too — the mixed-component case.** A tracking object
    /// with the right KEM seed and a different valid viewing seed once passed `bind`:
    /// the derived point was never compared with the registered one, so the scanner did its
    /// ECDH against an unrelated point and silently matched NOTHING, forever, with no setup
    /// error anywhere. The tutorial's claim that a mismatched tracking key is the failure
    /// `bind` surfaces was false for exactly half of this rung's tracking bytes.
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
        // The KEM half still verifies -- that is what made this silent.
        let (ek, _) = MlKem768::keygen(&mixed.kem_seed).unwrap();
        assert_eq!(ek, meta.ek, "the KEM half is untouched");
        assert!(matches!(
            SchemeId3::bind(&mixed, &meta),
            Err(Error::TrackingKeyMismatch)
        ));
    }

    /// **What the `ek` check does NOT cover, asserted rather than assumed.**
    ///
    /// `(d, z)` is two secrets and `ek` depends on `d` alone: FIPS 203's `KeyGen_internal`
    /// derives the encapsulation key from `d` and folds `z` into `dk` as the implicit-rejection
    /// secret. So §1's comparison is blind to every corruption confined to `z` -- half the
    /// tracking key, by bytes.
    ///
    /// This test was written expecting a mismatch and got a clean bind, which is how the gap was
    /// found. It asserts the boundary in both directions, because the interesting half is the
    /// second: a corrupt `z` is caught by nothing AND costs nothing. Decapsulating a genuine
    /// ciphertext runs the re-encryption check, that check passes, and the true shared secret
    /// comes back whatever `z` holds. `z` is consulted only on the rejection path, whose output
    /// is pseudorandom either way and which a scanner treats as "not ours" either way.
    ///
    /// So §1's MUST is aimed at exactly the half that matters, and the sentence justifying it --
    /// "a bit-flipped seed expands into a self-consistent keypair for a different key" -- is
    /// true of `d` and not of `z`. The requirement is right; its stated reason is half a reason.
    #[test]
    fn the_ek_check_is_blind_to_the_z_half_and_that_is_harmless() {
        let (meta, master, tracking) = SchemeId2::keygen(&unhex(SEED96)).unwrap();

        let mut z_corrupt = tracking.clone();
        z_corrupt.kem_seed[63] ^= 0x80; // the last bit of `z`

        // 1. `ek` does not move, so the check cannot see it.
        let (ek_good, _) = MlKem768::keygen(&tracking.kem_seed).unwrap();
        let (ek_z, _) = MlKem768::keygen(&z_corrupt.kem_seed).unwrap();
        assert_eq!(
            ek_good, ek_z,
            "ek depends on d alone -- FIPS 203 KeyGen_internal"
        );
        assert!(
            SchemeId2::bind(&z_corrupt, &meta).is_ok(),
            "and so bind accepts it, which is the gap this test records"
        );

        // 2. And it does not need to: a genuine payment is still found, and still spendable.
        let ann = SchemeId2::announce(&meta, &[0x77u8; 32]).unwrap();
        let scanner_z = SchemeId2::bind(&z_corrupt, &meta).unwrap();
        let m_z = SchemeId2::scan(&scanner_z, &ann).expect("z does not affect a valid decaps");
        let m_ok = SchemeId2::scan(&SchemeId2::bind(&tracking, &meta).unwrap(), &ann).unwrap();
        assert_eq!(m_z.stealth_address, m_ok.stealth_address);
        assert_eq!(m_z.shared_secret, m_ok.shared_secret);
        assert!(SchemeId2::spend_key(&master, &m_z).is_ok());
    }

    /// Two recipients, each other's material. This is the realistic version of the failure --
    /// not a cosmic ray but a wallet that loaded the wrong profile, or a scanning service handed
    /// one customer's tracking key and another's meta-address.
    #[test]
    fn a_tracking_key_from_a_different_keypair_is_rejected() {
        let mut other = unhex(SEED96);
        other[40] ^= 0xff;
        let (meta_a, _, tracking_a) = SchemeId2::keygen(&unhex(SEED96)).unwrap();
        let (meta_b, _, tracking_b) = SchemeId2::keygen(&other).unwrap();

        assert!(SchemeId2::bind(&tracking_a, &meta_a).is_ok());
        assert!(SchemeId2::bind(&tracking_b, &meta_b).is_ok());
        for (t, m) in [(&tracking_a, &meta_b), (&tracking_b, &meta_a)] {
            assert!(matches!(
                SchemeId2::bind(t, m),
                Err(Error::TrackingKeyMismatch)
            ));
        }
    }

    /// A rung will not bind another rung's material. `Malformed`, not `TrackingKeyMismatch`:
    /// the shape is wrong before any comparison is meaningful, and conflating the two would
    /// tell a user their key is corrupt when their scheme is.
    #[test]
    fn binding_across_rungs_is_malformed_not_a_mismatch() {
        let (meta2, _, tracking2) = SchemeId2::keygen(&unhex(SEED96)).unwrap();
        let (meta3, _, tracking3) = SchemeId3::keygen(&seed128()).unwrap();

        // ALL FOUR orientations, deliberately: the test fixture builds the schemeId 3 seed
        // by splicing a viewing scalar into the schemeId 2 seed, so the spending and KEM
        // halves AGREE across the rungs — which made the two omitted orientations pass
        // silently while the two tested ones carried the whole claim. A schemeId 2 bind
        // offered a schemeId 3 meta-address verified `ek`, ignored the registered viewing
        // point, and bound.
        for outcome in [
            SchemeId2::bind(&tracking3, &meta2),
            SchemeId2::bind(&tracking2, &meta3),
            SchemeId3::bind(&tracking2, &meta3),
            SchemeId3::bind(&tracking3, &meta2),
        ] {
            assert!(matches!(outcome, Err(Error::Malformed)));
        }
    }

    /// **The zero-address sentinel, and the check it would break.**
    ///
    /// Verified by mutation, and the first attempt found something better than a
    /// failing test: reinstating `stealth_address: [0u8; 20]` **does not compile**, because the
    /// parameter then goes unused and this workspace denies unused variables. The sentinel
    /// cannot come back by accident, only by someone writing `_stealth_address` on purpose.
    /// Mutated that way too, and these two tests fail while the other seven stay green.
    ///
    /// §2.8 lets a scanner compare the announced address against the one it derives. A parsed
    /// announcement carrying twenty zero bytes there would make that comparison
    /// reject every valid payment. This asserts the comparison
    /// succeeds on a genuine payment, which is the only way to know the sentinel is gone:
    /// a test that merely checked the field is non-zero would pass against a parser that
    /// substituted any other constant.
    #[test]
    fn a_parsed_announcement_survives_the_optional_address_comparison() {
        let (meta, _master, tracking) = SchemeId2::keygen(&unhex(SEED96)).unwrap();
        let built = SchemeId2::announce(&meta, &[0x33u8; 32]).unwrap();

        // Round-trip through the wire exactly as a scanner reading a log event would.
        let (addr, epk, md) = SchemeId2::announcement_to_bytes(&built);
        let parsed = SchemeId2::announcement_from_bytes(&addr, &epk, &md).unwrap();
        assert_eq!(parsed.stealth_address, built.stealth_address);
        assert_ne!(parsed.stealth_address, [0u8; 20], "the sentinel is gone");

        // §2.8's MAY, performed. This is the assertion that fails on the old code.
        let scanner = SchemeId2::bind(&tracking, &meta).unwrap();
        let m = SchemeId2::scan(&scanner, &parsed).expect("our own payment");
        assert_eq!(
            m.stealth_address, parsed.stealth_address,
            "the derived address must equal the announced one, or §2.8's comparison is a \
             guaranteed false negative"
        );
    }

    /// The same for schemeId 3, whose parser reads a point out of `epk` rather than a ciphertext.
    #[test]
    fn schemeid3_parses_the_address_too() {
        let (meta, _master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let built = SchemeId3::announce(&meta, &[0x44u8; 64]).unwrap();
        let (addr, epk, md) = SchemeId3::announcement_to_bytes(&built);
        let parsed = SchemeId3::announcement_from_bytes(&addr, &epk, &md).unwrap();

        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let m = SchemeId3::scan(&scanner, &parsed).expect("our own payment");
        assert_eq!(m.stealth_address, parsed.stealth_address);
        assert_ne!(parsed.stealth_address, [0u8; 20]);
    }

    /// A sender that announces one address and pays another is the failure §2.4 forbids, and
    /// §2.8's comparison is what catches it. Asserted from the scanner's side: a mismatched
    /// announced address does NOT stop the scan (the tag is what decides ownership) but IS
    /// visible to a caller performing the MAY. Both halves matter -- making it an error would
    /// hand a stranger a denial of service, and making it invisible would make §2.8 useless.
    #[test]
    fn a_lying_announced_address_is_detectable_without_being_an_error() {
        let (meta, _master, tracking) = SchemeId2::keygen(&unhex(SEED96)).unwrap();
        let built = SchemeId2::announce(&meta, &[0x33u8; 32]).unwrap();
        let (_real, epk, md) = SchemeId2::announcement_to_bytes(&built);

        let lie: [u8; 20] = core::array::from_fn(|i| 0xa0 ^ (i as u8));
        let parsed = SchemeId2::announcement_from_bytes(&lie, &epk, &md).unwrap();

        let scanner = SchemeId2::bind(&tracking, &meta).unwrap();
        let m = SchemeId2::scan(&scanner, &parsed).expect("still ours -- the tag decides");
        assert_ne!(
            m.stealth_address, parsed.stealth_address,
            "and §2.8 can see the lie"
        );
        assert_eq!(
            m.stealth_address, built.stealth_address,
            "the derived address is the truth"
        );
    }

    /// The cache is the *verified* key, not the registry's copy of it.
    ///
    /// A tempting implementation of `bind` compares and then stores `meta.ek`. It passes every
    /// test above and is wrong in one case: if the comparison were ever weakened, the value fed
    /// to the combiner would be the one from the registry while decapsulation used a different
    /// key, and the two halves of the derivation would disagree. Storing the recomputed value
    /// makes that impossible rather than merely unlikely.
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

    /// The redacted `Debug` impls leak nothing, checked in THIS crate.
    ///
    /// A sibling crate has a test covering both crates' types from one place, which is the
    /// better arrangement in a tree carrying both. It is not one a tree carrying only this crate
    /// can rely on, and these `Debug` impls are exactly as reachable there — so the obligation is
    /// checked here rather than cited across a boundary a single-rung export removes.
    ///
    /// schemeId 3 deliberately: it is the per-payment rung with a viewing secret, so `Master`,
    /// `Tracking` and `Scanner` carry every kind of secret these types can hold.
    #[test]
    fn redaction_leaks_no_secret() {
        let (meta, master, tracking) = SchemeId3::keygen(&seed128()).unwrap();
        let scanner = SchemeId3::bind(&tracking, &meta).unwrap();
        let ann = SchemeId3::announce(&meta, &[0x77u8; 64]).unwrap();
        let matched = SchemeId3::scan(&scanner, &ann).expect("our own announcement");

        let hex = |b: &[u8]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
        // The decimal form a derived `Debug` would print: "17, 32, 9" for [17, 32, 9]. Eight
        // leading bytes identify a secret unambiguously, and a decimal list leaks as thoroughly
        // as hex — which is the whole reason these impls are hand-written.
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
        // A non-secret field still prints: a `Debug` that hid everything would be useless and
        // would pass every assertion above for the wrong reason. Shown fields go through the
        // derived formatter, so the address appears as the decimal byte list — which is the same
        // form the assertions above search for, and the reason they search for it.
        assert!(
            rendered.contains(&dec(&matched.stealth_address)),
            "the stealth address is public by construction and must still be shown"
        );
    }

    /// The demonstration seed `harness/payment/README.md` states, EXECUTED, on both rungs.
    ///
    /// The committed payment receipts -- 67 940 / 109 940 for schemeId 2, 69 510 / 111 510 for
    /// schemeId 3 -- are receipts of two specific announcements, and under EIP-7623 a calldata
    /// byte costs 1 token if it is zero and 4 if it is not. The figure is therefore a function
    /// of these exact bytes, and a reader reproducing it from any other seed gets a different
    /// number and concludes the receipt is wrong.
    ///
    /// The seed was named in `measured.json` and stated nowhere, and the emitter that knows it
    /// lives in a crate the standalone export does not carry. This is the recipe in executable
    /// form, in a crate the export DOES carry.
    ///
    /// **The whole variable part of the calldata is pinned, not just the payload.** An earlier
    /// version asserted the two field lengths and the payload's zero count and discarded the
    /// address -- and `stealthAddress` is an `announce()` argument, so a derived address with
    /// one more zero byte in it moves the floor by 30 gas with every assertion still green.
    /// A digest over `stealthAddress ‖ ephemeralPubKey ‖ metadata` leaves nothing out.
    #[test]
    fn the_documented_demonstration_seed_reproduces_the_measured_payload() {
        fn walk<S: StealthScheme>(keygen_len: usize) -> ([u8; 20], Vec<u8>, Vec<u8>) {
            // seed[i] = (i * 7 + 3 + salt) mod 256, salt = 0.
            let keygen_seed: Vec<u8> = (0..keygen_len as u32)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
                .collect();
            let (meta, _master, _tracking) = S::keygen(&keygen_seed).unwrap();
            // Sender master [0x5a; 32], counter 0 -- the first draw.
            let mut sender = pqsa_core::SenderState::resume([0x5a; 32], 0);
            let ann = S::announce(&meta, &sender.draw_seed::<S>().unwrap()).unwrap();
            S::announcement_to_bytes(&ann)
        }

        // (keygen seed length, epk width, metadata width, zero bytes, digest) -- §6's wire
        // table for the rung, then the two properties the receipt rests on.
        let rungs: [(usize, usize, usize, usize, &str); 2] = [
            (
                96,
                1088,
                8,
                1,
                "518b4b3184372741d90ccdeaf29d1ea32b73da56f7badce066612526617a11dc",
            ),
            (
                128,
                33,
                1096,
                2,
                "25df977bb2a67c6089cd109ebbbdd0a1c0d3cc28e548ba12ccd3094573e79e27",
            ),
        ];

        for (i, (len, epk_w, meta_w, zeros, want)) in rungs.iter().enumerate() {
            let (addr, epk_field, metadata) = if i == 0 {
                walk::<SchemeId2>(*len)
            } else {
                walk::<SchemeId3>(*len)
            };
            let sid = if i == 0 { 2 } else { 3 };
            assert_eq!(
                epk_field.len(),
                *epk_w,
                "§6: schemeId {sid} `ephemeralPubKey` width"
            );
            assert_eq!(
                metadata.len(),
                *meta_w,
                "§6: schemeId {sid} `metadata` width"
            );

            let blob: Vec<u8> = addr
                .iter()
                .chain(epk_field.iter())
                .chain(metadata.iter())
                .copied()
                .collect();
            assert_eq!(
                blob.iter().filter(|b| **b == 0).count(),
                *zeros,
                "schemeId {sid}: the measured calldata carries exactly {zeros} zero byte(s), and \
                 EIP-7623 prices a zero at 1 token against a nonzero at 4 -- this count is what \
                 the committed receipt rests on"
            );

            let digest = Sha256::digest(&blob);
            assert_eq!(
                digest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                *want,
                "schemeId {sid}: `stealthAddress ‖ ephemeralPubKey ‖ metadata` is not the \
                 measured one. Every byte the receipt was taken over is in this digest, so a \
                 mismatch means the stated seed no longer reproduces the measurement"
            );
        }
    }
}
