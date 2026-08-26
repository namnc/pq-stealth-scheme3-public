//! The shape every rung shares: one trait, the guards, and the errors.
//!
//! # What this crate owns
//!
//! [`StealthScheme`] is the interface every rung of the ladder implements, and it exists so
//! that a caller — a wallet, a conformance runner, a scanner service — can be written once
//! against the ladder rather than once per rung. Everything rung-specific lives in a rung
//! crate; **which rung crates a given tree carries depends on that tree**, and this one
//! names none of them so the sentence stays true in a tree carrying one.
//!
//! [`SenderState`] is the other half, and it is a **guard rather than a convenience**. §5 of
//! the common ERC requires announcement seeds to be derived rather than drawn freely, and the
//! reason is not hygiene: reusing a seed reuses the KEM message, which reuses `ss`, which
//! repeats a stealth address. A sender that draws its own bytes can violate that and nothing
//! will tell it. So the type that hands out seeds is the only way to get one.
//!
//! # What this crate deliberately cannot do
//!
//! It has **no cryptography in it**, and no dependency that does. It cannot construct a key,
//! derive an address, or produce an announcement. That is what makes it reviewable in an
//! afternoon and what stops "the interface" quietly becoming a fourth implementation.
//!
//! It also **cannot represent a sender-side channel**, which belongs to the pairwise-channel
//! rung rather than being a gap here. That rung's specification requires the separation be
//! structural, because a runtime filter is guard-by-documentation — and a tree carrying
//! only a per-payment rung has neither the crate nor the section, which is why neither is
//! named as a pointer here.
//!
//! # Where the specification is
//!
//! §1 for the definitions and §5 for the seed derivations these guards enforce. Each item
//! below cites the section it implements.
//!
//! **Sections are cited by number and not by file, deliberately.** One numbering runs across
//! every document that specifies a rung of this ladder, so `§1` resolves in whichever of them
//! a reader holds — and a tree carrying a different subset of those documents does not turn
//! this header into a pointer at nothing.
//!
//! # Status
//!
//! **Implemented against the committed conformance vectors**, which existed before any
//! of these bodies did.

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// A 32-byte value: a seed, a scalar, a shared secret, or a hash output.
///
/// Deliberately not distinct newtypes at this stage. Naming each role separately is the right
/// end state and it is a large amount of surface to review before the derivations it protects
/// are written, so it is deferred deliberately rather than overlooked.
pub type Bytes32 = [u8; 32];

/// §5's domain separator for the sender-entropy derivation.
const DS_SENDER: &[u8] = b"pq-stealth/sender-seed/v1";

/// §5's canonical KEM name for the deployed path. `kem_id` length-prefixes it.
const KEM_NAME: &[u8] = b"ML-KEM-768";

/// The view tag's width, in bytes. §1.
///
/// **Eight, and it is an exact matcher rather than a prefilter.** ML-KEM rejects implicitly, so
/// decapsulating a ciphertext addressed to somebody else returns a pseudorandom shared secret
/// and no error: the KEM gives a scanner no signal of its own, the view tag is the only signal
/// there is, and its width is how much of that signal a scanner gets. At one byte a scanner does
/// not know, and it has to resolve the ambiguity with a chain-state query — which is the
/// disclosing step §9's RPC paragraph is about. A narrow tag does not avoid that leak; it makes
/// it necessary.
///
/// It lives here rather than in each scheme's crate because §1 owns it and **every** announcement
/// in the ladder carries one — including the pairwise rungs' first contacts.
/// At eight bytes it also subsumes the pairwise-channel rungs' confirm tag, which is why a
/// channel memo carries one field rather than two. Named rather than linked: the crate that
/// defines it is not in every tree that carries this one, and a rustdoc link into an absent
/// crate renders as a dead path.
///
/// Not a `u8`-typed constant and not an integer type for the tag itself: an integer lets a call
/// site format the value at the wrong width, which produces a well-formed announcement that no
/// conforming implementation matches. The tag is bytes.
pub const VIEW_TAG_BYTES: usize = 8;

/// What went wrong.
///
/// Per §2.5 and §4.5, **a scanner's negative outcome is never one of these**: "not ours" is
/// the overwhelmingly common case on a permissionless event stream, and an error path a
/// stranger can trigger is a denial of service. Scanning returns [`Option`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A length, a tag byte or a field ordering that the specification rejects. §1.
    Malformed,
    /// A seed whose reduction yielded no valid scalar, after the retry bound of §1.
    NoValidScalar,
    /// §2.1's guard fired: a 32-byte window of the delegated object equalled the spending
    /// seed, so delegating it would hand over spending authority. See
    /// [`reject_if_spending_key_is_delegated`].
    SpendingKeyDelegated,
    /// §5's per-sender counter is exhausted. A wallet MUST NOT wrap it: index reuse is seed
    /// reuse, and §5 requires that a rejected index never be retried.
    CounterExhausted,
    /// The KEM refused — encapsulation to a malformed key, or decapsulation of a ciphertext
    /// that is not one. **Never surfaced by a scanner**, which treats it as "not ours".
    Kem,
    /// **This announce seed is unusable; draw the next one.** §5's rejection rule, and the only
    /// error a sender is expected to LOOP on.
    ///
    /// §5 requires that an announce seed whose derived material is invalid advance the sender's
    /// index rather than being retried, and that the rejected index never be reused. schemeId 3
    /// is where this is reachable: its seed is `ephemeral_seed(32) ‖ encap_seed(32)` and the
    /// first half must be a valid secp256k1 scalar, which a uniformly drawn 32 bytes is not with
    /// probability about 2⁻¹²⁸ per draw.
    ///
    /// # Why it is its own variant, and why that is not pedantry
    ///
    /// A bare [`Error::NoValidScalar`] would not do — that is the same error a *keygen*
    /// returns when the master spending seed is unusable, and the same one a scan returns
    /// when a derived offset is. The loop §5 asks for could not be written against it:
    ///
    /// ```text
    /// loop {
    ///     let seed = sender.draw_seed::<S>()?;
    ///     match S::announce(meta, &seed) {
    ///         Ok(a) => return Ok(a),
    ///         Err(Error::NoValidScalar) => continue,   // ALSO catches unrelated failures
    ///         Err(e) => return Err(e),
    ///     }
    /// }
    /// ```
    ///
    /// A caller writing that retries forever on a permanently broken meta-address, and one that
    /// declines to write it violates §5 on the payment where it matters. **A specification that
    /// requires a retry needs an API that says which failure to retry** — a property
    /// visible only by writing the loop above, not by reading the interface.
    SeedRejected,
    /// A tracking key does not belong to the meta-address it was asked to scan for: `ek`
    /// recomputed from its `(d, z)` seed is not the `ek` in the registry — or, on the hybrid
    /// rungs, the point derived from the delegated viewing scalar is not the registered
    /// viewing point. §1 requires BOTH comparisons (every delegated component against its
    /// registered counterpart) at least once before scanning, and [`StealthScheme::bind`] is
    /// where they run: either half wrong means a scanner that silently matches nothing,
    /// forever, with no later error.
    ///
    /// **This is the one setup error the specification says MUST surface**, and the reason is
    /// specific: a bit-flipped `(d, z)` expands through `KeyGen_internal` into a
    /// self-consistent keypair for a *different* key, so FIPS 203's own `dk` check passes and
    /// every subsequent scan returns "not mine" with no error anywhere. A recipient sees zero
    /// payments for ever and has nothing to look at. There is no other mechanism in the
    /// document by which a corrupt tracking key is detectable.
    ///
    /// It is emphatically NOT a scan outcome. `scan` returns [`Option`] because `announce()` is
    /// permissionless (§2.5); this is the recipient's own key being wrong, which is not
    /// something a stranger can trigger.
    TrackingKeyMismatch,
    /// **No conforming schemeId 6 announcement can be emitted, because §4.6 is an open
    /// decision.** §4.4: ERC-5564's `announce()` takes the stealth address as an argument, the
    /// address MUST be the one §4.6's mapping yields for `opk_ds`, and the mapping is not yet
    /// specified — so the one field the call needs beyond the two §4.3 defines has no defined
    /// value. schemeId 6's `announce` returns this unconditionally.
    ///
    /// # Why a variant rather than a panic, an `unimplemented!` or a missing method
    ///
    /// The refusal is **specified behaviour**, not an implementation gap. §4.4 forbids every
    /// substitute — the zero address, the recipient's registered address, any value not derived
    /// from `opk_ds` — so the correct output of a conforming `announce` today is "no
    /// announcement", stated as a value a caller can match on. A panic would make the
    /// specification's own state an abnormal exit; an unimplemented method would read as work
    /// remaining rather than a decision pending. The rung is *unemittable*, and this variant is
    /// that sentence as data.
    ///
    /// It is NOT retryable and NOT an input defect: no seed, meta-address or counter changes
    /// it. Only a revision of §4.6 does, at which point the variant is deleted and every
    /// caller that matched on it fails to compile — which is the desired upgrade path, since
    /// each such site was written knowing the address mapping was open.
    AddressMappingOpen,
}

/// What [`StealthScheme::keygen`] returns: the published meta-address, the secret a recipient
/// keeps, and the secret it may delegate.
///
/// A named alias rather than a bare tuple because the three are easy to transpose at a call
/// site and two of them are secrets — `Master` never leaves the device and `Tracking` may.
pub type Keys<S> = (
    <S as StealthScheme>::Meta,
    <S as StealthScheme>::Master,
    <S as StealthScheme>::Tracking,
);

/// One rung of the ladder.
///
/// # Why associated types rather than concrete ones
///
/// The five rungs differ in what a meta-address, an announcement and a match *are*: schemeId
/// 2's announcement is a KEM ciphertext and a view tag, schemeId 4's later payments are
/// 8-byte memos, and schemeId 6's one-time key is an ML-DSA public key. A trait over
/// concrete byte vectors would push every one of those distinctions into runtime parsing,
/// which is where wire-format defects live.
///
/// # The one thing this trait asserts about all five
///
/// **Keygen is deterministic in its seed.** Every rung derives its keys from bytes the caller
/// supplies, and nothing here draws randomness. That is what makes conformance vectors
/// possible at all, and §5's seed-only recovery depends on it.
///
/// Specification: §1 for the vocabulary, §6 for the wire and registry rules every
/// implementation of this trait must satisfy.
pub trait StealthScheme {
    /// The ERC-5564 `schemeId` this rung claims.
    ///
    /// **None of 2, 3, 4, 5 or 6 is reserved with the ERC-5564 authors** — item 1 of the
    /// common ERC's Open before submission. Until they are, this constant is a proposal, and
    /// publishing material under an id that means something else has a live example: the
    /// upstream reference emits Spirit vectors labelled `schemeId: 4`, which this
    /// specification assigns to the ML-KEM-only pairwise channel.
    const SCHEME_ID: u64;

    /// Human-readable name, for vector files and test output. Never parsed.
    const NAME: &'static str;

    /// The keygen seed's length in bytes; an implementation MUST reject any other. §2.1 makes
    /// this 96 for schemeId 2 and §2.9 makes it 128 for schemeId 3.
    const KEYGEN_SEED_BYTES: usize;

    /// The announce seed's length in bytes, per §5.
    const ANNOUNCE_SEED_BYTES: usize;

    /// What a recipient publishes through ERC-6538. §6's registry column gives the size.
    type Meta;
    /// What a recipient keeps in order to spend. Never leaves the device.
    type Master;
    /// What a recipient may hand to a scanning service. §2.1 permits delegating this and
    /// **only** this; §9 records that a delegated scanner learns the entire payment graph.
    type Tracking;
    /// What a sender publishes through ERC-5564 `announce()`. §6's wire table gives the shape.
    type Announcement;
    /// What a successful scan yields, and what spending consumes.
    type Match;
    /// A tracking key **already checked against a meta-address**, plus whatever scanning needs
    /// more than once. Produced only by [`Self::bind`], which is what makes §1's check
    /// unskippable: there is no other way to obtain the argument [`Self::scan`] takes.
    ///
    /// It is also where the values that do not change per announcement live. Deriving `ek` and
    /// the viewing point inside `scan` costs a full ML-KEM key generation on every event a
    /// scanner looks at, including every foreign one, which prices adversarial traffic at the
    /// scanner's expense and overruns the per-announcement cost floor §2 states.
    type Scanner;
    /// The one-time key spending uses.
    ///
    /// **An associated type and not `Bytes32`.** For schemeIds 2
    /// to 5 it is a 32-byte secp256k1 scalar. For schemeId 6 it is the parameter set's
    /// secret-key encoding of `(CRS, tr, key_j, t0_ot, s1, s2)` — §4.7's `OSKGen` output, which
    /// §4.8 passes to `Sign`. Fixing this to 32 bytes made the trait unimplementable by a
    /// conforming schemeId 6 without truncating a lattice signing key, while the crate
    /// documentation claimed the interface covered all five rungs. An API contract mismatch,
    /// separate from that rung being undeployable.
    type SpendKey;

    /// Derive a recipient's keys from `seed`, which MUST be [`Self::KEYGEN_SEED_BYTES`] long.
    ///
    /// Deterministic: the same seed gives the same three outputs, on every platform and in
    /// every process. §5's seed-only recovery is built on that.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a wrong length, [`Error::NoValidScalar`] if a derived scalar is
    /// invalid after §1's retry bound, [`Error::SpendingKeyDelegated`] if §2.1's guard fires.
    fn keygen(seed: &[u8]) -> Result<Keys<Self>, Error>
    where
        Self: Sized;

    /// Produce an announcement for `meta`, using `seed` from [`SenderState::draw_seed`].
    ///
    /// **The seed parameter is not a convenience.** §5 requires it be derived per payment, and
    /// taking it as a parameter is what lets [`SenderState`] be the only source of one.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a meta-address this rung does not recognise, [`Error::Kem`] on
    /// encapsulation failure.
    fn announce(meta: &Self::Meta, seed: &[u8]) -> Result<Self::Announcement, Error>;

    /// Check a tracking key against the meta-address it will scan for, and cache what scanning
    /// needs repeatedly. **Every scan goes through this first, by construction.**
    ///
    /// §1: *"A recipient or a delegated scanner MUST recompute `ek` from its `(d, z)` seed and
    /// compare it against the `ek` in the registered meta-address, at least once before
    /// scanning"* — and, on the hybrid rungs, the same sentence covers the viewing half: the
    /// point derived from the delegated viewing scalar MUST be compared against the
    /// registered viewing point in the same pass. Those comparisons are the whole reason
    /// this function exists, and the section
    /// states its own justification: without the comparison there is **no mechanism anywhere in
    /// the document** by which a corrupt tracking key surfaces.
    ///
    /// # Why a separate step and not a check inside `scan`
    ///
    /// Three reasons, and the first is the one that matters.
    ///
    /// **It cannot be skipped.** [`Self::scan`] takes a [`Self::Scanner`] and nothing else
    /// produces one, so an implementation that forgets the check does not compile. A
    /// `verify_tracking()` a caller is asked to remember is the same defect with a longer
    /// name — and this repository's standing rule is that a correction is not done until the
    /// mechanism is prevented rather than the symptom removed.
    ///
    /// **It runs once.** §1 says "at least once before scanning", not per announcement. Doing
    /// it inside `scan` recomputes an ML-KEM key generation for every event a scanner looks at,
    /// foreign ones included — which the per-payment document's cost
    /// floor of one decapsulation plus one scalar multiplication forbids.
    ///
    /// **It separates a setup error from a scan outcome.** `scan` returns [`Option`] because
    /// `announce()` is permissionless; a wrong tracking key is the recipient's own state being
    /// broken, and returning [`None`] for it reports "no payments" where the truth is "you
    /// cannot see your payments".
    ///
    /// # Errors
    ///
    /// [`Error::TrackingKeyMismatch`] if the recomputed `ek` differs from the registered one
    /// — or, on the hybrid rungs, if the derived viewing point differs from the registered
    /// one: BOTH delegated components are compared, because either half wrong is a scanner
    /// that finds nothing with no error. [`Error::Malformed`] if the tracking key or the
    /// meta-address is not this rung's shape.
    fn bind(tracking: &Self::Tracking, meta: &Self::Meta) -> Result<Self::Scanner, Error>;

    /// Is this announcement ours?
    ///
    /// **Returns [`Option`], never [`Result`].** §2.5 and §4.5: every negative outcome is "not
    /// ours" rather than an error, because `announce()` is permissionless and an error path is
    /// a denial of service a stranger can trigger. A malformed announcement, a foreign one and
    /// a KEM failure are all [`None`].
    ///
    /// # Why the meta-address is an argument, and why it is checked
    ///
    /// §2.5 opens *"Given the tracking key, the meta-address, and an announcement already
    /// classified as schemeId 2 per §6"* — **three** inputs. A two-input signature cannot
    /// satisfy that sentence: a [`Self::Match`] carries a stealth address,
    /// the address is `spending_pk + H(ss)·G`, and a tracking key does not carry
    /// `spending_pk`. It cannot: §2.1 delegates only what a scanner needs to *detect*, and the
    /// spending point is published in the registry rather than delegated.
    ///
    /// **So a two-input API cannot implement the section it cites.** Adding the point to
    /// [`Self::Tracking`] was the other option and is worse: it makes the delegated object
    /// carry a field §2.1 does not list, and the delegated object's exact contents are what
    /// the 65-offset window scan is defined over.
    ///
    /// Both inputs live behind [`Self::bind`] because a
    /// three-argument form would let a caller scan with a tracking key belonging to a different
    /// meta-address — which is the failure §1 has a MUST about. The fix is not to add a check
    /// to this function but to make the checked pair the only thing it accepts.
    ///
    /// This is the defect class documented stubs exist to surface — the signatures compile, so
    /// nothing objected until a body had to satisfy the specification.
    ///
    /// # What this function does NOT do: replay deduplication
    ///
    /// §2.5 states that *a derived stealth address identifies ONE payment* and that a scanner
    /// **MUST NOT** present two announcements deriving the same address as two payments. This
    /// function cannot satisfy that requirement and does not try: it takes ONE announcement,
    /// holds no state between calls, and returns the same [`Self::Match`] every time it is
    /// handed the same input. `announce()` is permissionless, so a verbatim replay is free to
    /// arrange and both copies pass every check here.
    ///
    /// **The requirement therefore binds the CALLER'S state**, which is the only thing that sees
    /// more than one announcement: it keeps the set of stealth addresses already presented and
    /// drops a match whose address is in it. Stating that here rather than leaving it implicit,
    /// because a caller who reads this signature as "the scanner" builds the behaviour §2.5
    /// forbids and nothing in this crate objects.
    ///
    /// **That set must outlive the scan, not the batch.** The log is append-only and `announce()`
    /// is permissionless, so the replay is under no obligation to arrive in the same batch as the
    /// payment — it can land in a later block range, after a restart, or in a re-scan. A caller
    /// that deduplicates within one call satisfies §2.5 for that call and breaks it across two.
    fn scan(scanner: &Self::Scanner, ann: &Self::Announcement) -> Option<Self::Match>;

    /// Derive the one-time spending key for a match.
    ///
    /// **A caller MUST have observed [`Self::scan`] return [`Some`] for this announcement
    /// first.** §4.7 states that obligation for schemeId 6 explicitly; the upstream
    /// reference's own caller does not discharge it — it decapsulates and derives
    /// without scanning.
    ///
    /// # Errors
    ///
    /// [`Error::Kem`] or [`Error::NoValidScalar`] on the classical rungs;
    /// [`Error::Malformed`] where a rung refuses malformed or cross-rung material
    /// (schemeId 6 does, for a wrong-width match or a crossed master). The concrete
    /// set is the implementation's.
    fn spend_key(master: &Self::Master, m: &Self::Match) -> Result<Self::SpendKey, Error>;

    /// The stealth address a match derives.
    ///
    /// # Why the trait needs this at all
    ///
    /// [`Self::Match`] is an associated type, so a caller generic over the rung cannot reach
    /// inside it — and §2.8 lets a scanner **compare the announced address against the one it
    /// derives**. Without an accessor that comparison is available only to code that knows the
    /// concrete rung, which means the conformance runner cannot perform it, a generic wallet
    /// cannot perform it, and a permission the specification grants is one this API withholds.
    ///
    /// Without it, an end-to-end demonstration generic over the rung can derive the
    /// address, announce it, scan it, and then not say whether the two agreed — an
    /// interface that compiles while no body can satisfy the specification.
    fn match_address(m: &Self::Match) -> [u8; 20];

    /// Serialise a meta-address for ERC-6538 `registerKeys`. §6's registry rules.
    fn meta_to_bytes(meta: &Self::Meta) -> Vec<u8>;

    /// Parse a meta-address read out of the registry. [`None`] if it is not one of this rung's.
    fn meta_from_bytes(bytes: &[u8]) -> Option<Self::Meta>;

    /// Serialise an announcement into ERC-5564's `announce()` arguments —
    /// `(stealthAddress, ephemeralPubKey, metadata)`, in that order.
    ///
    /// §6's wire table fixes the last two, and the field ORDER within `metadata` is where
    /// the older external implementations diverge from this document.
    ///
    /// # `stealthAddress` is a return value
    ///
    /// ERC-5564's call is
    /// `announce(schemeId, stealthAddress, ephemeralPubKey, metadata)` — **four arguments** —
    /// and this returned two, so **an implementer following this API could not make a
    /// conforming call at all.** The tutorial followed the API and told a reader to call
    /// `announce()` "with those two fields", which is not a call that exists.
    ///
    /// §2.4 requires the field be the address the announcement's own payment derives, and names
    /// the failure: *"a sender that announces one address and pays another has made a payment
    /// its recipient cannot find."* Filling a placeholder is worse than wrong — §3.4 records
    /// that it marks the announcement as a channel opening to any observer — and a scanner
    /// exercising §2.8's comparison rejects it.
    ///
    /// So the address is carried in [`Self::Announcement`] and returned here, rather than left
    /// for a caller to recompute: recomputing it needs `ss`, which the sender has and a
    /// serialiser should not have to ask for twice.
    fn announcement_to_bytes(ann: &Self::Announcement) -> ([u8; 20], Vec<u8>, Vec<u8>);

    /// Parse an announcement off the event stream. [`None`] if it is not one of ours, which is
    /// the common case and is not an error.
    ///
    /// # Three arguments, mirroring [`Self::announcement_to_bytes`], and the third is load-bearing
    ///
    /// A signature of `(epk, metadata)` — the two payload fields alone — would leave both
    /// rungs filling `stealth_address` with **twenty zero bytes**. §2.8 lets a scanner
    /// compare the announced address against the one it derives, and a caller implementing
    /// that MAY against such a parsed announcement rejects **every valid payment**, because
    /// the announced side is always zero. Reserialising such a parsed announcement emits
    /// zero as ERC-5564's `stealthAddress` for the same reason.
    ///
    /// The address was never missing from the world. `announce(schemeId, stealthAddress,
    /// ephemeralPubKey, metadata)` is four arguments and a scanner reading a log has all of
    /// them; a parser that does not ask for one encodes a gap in its own API
    /// rather than a gap in the event, and a caller has no way to tell those apart — which
    /// is what makes it dangerous rather than merely untidy.
    ///
    /// A sentinel is the wrong shape for "this field was not supplied" whenever the absent
    /// value is indistinguishable from a real one. `[0u8; 20]` is a valid Ethereum address.
    fn announcement_from_bytes(
        stealth_address: &[u8; 20],
        epk: &[u8],
        metadata: &[u8],
    ) -> Option<Self::Announcement>;
}

/// The rungs whose spend key is an **exportable** secret — a secp256k1 scalar a caller hands
/// to an ordinary ECDSA signer, which is how schemeIds 2 to 5 spend.
///
/// # Why this is not on [`StealthScheme`]
///
/// On the shared trait, every rung would have to implement it — schemeId 6 included,
/// exposing the packed lattice signing key as raw bytes from a rung whose
/// specification says the one-time key "MUST NOT be
/// retained, exported, logged, backed up or transmitted" (§4.8). A trait method is an
/// export path: generic code could copy the bytes out without ever naming the rung it was
/// betraying. So the accessor lives here, the classical rungs implement it because handing
/// the scalar to a signer IS their spend path, and schemeId 6 deliberately does not — its
/// spending capability is a consuming `sign` on the concrete type, one signature per
/// derivation, recompute rather than cache.
///
/// A slice rather than `[u8; 32]`, still: the width belongs to the rung, and a future
/// exportable-key rung need not carry a scalar.
pub trait ExportableSpendKey: StealthScheme {
    /// The one-time spending key as bytes, for a caller generic over the exportable rungs.
    fn spend_key_bytes(k: &Self::SpendKey) -> &[u8];
}

/// §5's domain separator for the keygen-seed derivation. Distinct from the announce seed's.
const DS_KEYGEN: &[u8] = b"pq-stealth/keygen/v1";

/// §5's keygen-seed derivation: one backed-up master to every scheme's keygen seed.
///
/// ```text
/// keygen_seed(schemeId, rung, j) = HKDF-SHA256(
///     ikm  = keygen_master(32),
///     salt = absent,
///     info = "pq-stealth/keygen/v1" ‖ u64be(schemeId) ‖ u64be(|rung|) ‖ rung ‖ u64be(j),
///     L    = the scheme's keygen-seed length)
/// ```
///
/// **`HKDF-SHA256` is the complete RFC 5869 construction — Extract then Expand — and an absent
/// salt is RFC 5869 §2.2's 32 zero bytes.** §5 says so normatively, and it says so because an
/// independent implementer working from the document found the naming ambiguous: reading `ikm =
/// keygen_master` as a PRK and running Expand alone is a coherent reading that produces a
/// different seed for every `schemeId` and every rung, so two conforming wallets would derive
/// disjoint key material and neither could see the other's payments.
///
/// # Why this exists
///
/// The crates implement the *scheme* — keygen, announce, scan, spend — and every one of them
/// takes a keygen seed as an input. §5's recovery layer sits above that and derives the seed,
/// which is a wallet's job rather than a rung's, so nobody wrote it. The consequence was
/// specific and worth stating: `V6-01` and `V6-04` pin this derivation, the fixtures existed,
/// an independent re-derivation agreed with them, and **the conformance runner could not
/// execute either row because there was no function to call**. A requirement with a fixture and
/// no implementation is not covered; it is documented.
///
/// `j` starts at 0 and increments on rejection — §5 requires that a rejected index never be
/// retried and that the accepted `j` be recorded with the backup, per (`schemeId`, `rung`) pair.
/// That bookkeeping is the caller's; this function is the derivation only.
///
/// # Errors
///
/// [`Error::Malformed`] if `master` is not 32 bytes, or if `length` is zero or exceeds
/// HKDF-SHA256's 255 × 32 = 8 160-byte output limit.
pub fn keygen_seed(
    master: &[u8],
    scheme_id: u64,
    rung: &[u8],
    j: u64,
    length: usize,
) -> Result<Vec<u8>, Error> {
    if master.len() != 32 || length == 0 || length > 255 * 32 {
        return Err(Error::Malformed);
    }
    let mut info = Vec::with_capacity(DS_KEYGEN.len() + 24 + rung.len());
    info.extend_from_slice(DS_KEYGEN);
    info.extend_from_slice(&scheme_id.to_be_bytes());
    info.extend_from_slice(&(rung.len() as u64).to_be_bytes());
    info.extend_from_slice(rung);
    info.extend_from_slice(&j.to_be_bytes());

    // `None` is RFC 5869's absent salt, which Extract expands to HashLen zero bytes. Written as
    // `None` rather than as an explicit `[0u8; 32]` so the intent is the RFC's word and not a
    // constant a reader has to check against it -- the two are equal because HMAC zero-pads a
    // short key to the block size, and `keygen_seed_matches_an_explicit_zero_salt` asserts it.
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master);
    let mut out = vec![0u8; length];
    hk.expand(&info, &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// The only way to get an announce seed, which is the point.
///
/// # Why a type and not a function
///
/// §5 requires `seed_i = SHAKE256(domain ‖ master ‖ u64be(i))` with `i` never reused, and a
/// free function taking `i` puts the counter in the caller's hands. Holding it here means a
/// wallet cannot reuse an index without reaching for a second `SenderState`, which is
/// something a reviewer can see.
///
/// # What must be persisted
///
/// **`master` and `i` together**, per §5. A wallet that cannot persist `i` MUST NOT use a
/// derived seed at all — losing the counter and continuing is index reuse, and index reuse
/// repeats a stealth address.
///
/// Specification: §5, in full.
pub struct SenderState {
    _master: Bytes32,
    _counter: u64,
}

impl SenderState {
    /// Resume from a persisted `(master, counter)` pair, where **`counter` is the next UNUSED
    /// index** — not the last used one.
    ///
    /// §5 defines `i` as strictly increasing and never reused, so `resume(m, 42)` means 42 has
    /// not been drawn yet: the next [`Self::draw_seed`] consumes 42 and [`Self::counter`] then
    /// returns 43. A fresh sender starts at 0.
    ///
    /// **Off by one in the other direction repeats the previous index after every restart**,
    /// which repeats the seed, the KEM message and the stealth address, and links two payments
    /// publicly and permanently. Stated on this type because a caller reads the type, not the
    /// tutorial, and "next unused" versus "last used" is exactly the off-by-one that repeats a seed.
    ///
    /// There is deliberately **no** constructor that starts a fresh counter without the caller
    /// saying so: "new" and "resumed" look identical at a call site, and choosing wrong reuses
    /// every index.
    #[must_use]
    pub fn resume(master: Bytes32, counter: u64) -> Self {
        Self {
            _master: master,
            _counter: counter,
        }
    }

    /// The next unused index, to persist alongside `master`. Read it after every
    /// [`Self::draw_seed`] and store what it returns — not what was passed to
    /// [`Self::resume`].
    #[must_use]
    pub fn counter(&self) -> u64 {
        self._counter
    }

    /// Draw the next announce seed for rung `S`, advancing the counter.
    ///
    /// # Why the rung is a type parameter
    ///
    /// §5 binds the rung into the derivation, and binding [`StealthScheme::SCHEME_ID`] alone
    /// is **not sufficient** — the three schemeId 6 levels share an id and a seed length, so
    /// one master and one counter would produce the byte-identical KEM message for all three.
    /// The upstream guard records that as a defect it actually had. §5's rule is
    /// per-`(schemeId, rung)`.
    ///
    /// # Errors
    ///
    /// [`Error::CounterExhausted`] rather than wrapping.
    pub fn draw_seed<S: StealthScheme>(&mut self) -> Result<Vec<u8>, Error> {
        self.draw(S::SCHEME_ID, S::NAME, S::ANNOUNCE_SEED_BYTES)
    }

    /// §5's rejection loop, as one call, so a caller cannot get it wrong.
    ///
    /// Draws seeds and hands each to `attempt` until one is accepted, advancing the index on
    /// every rejection and never reusing one. Stops on [`Error::CounterExhausted`], on any error
    /// other than [`Error::SeedRejected`], or after `tries` attempts.
    ///
    /// ```no_run
    /// # use pqsa_core::{SenderState, StealthScheme, Error};
    /// # fn f<S: StealthScheme>(meta: &S::Meta, sender: &mut SenderState)
    /// #     -> Result<S::Announcement, Error> {
    /// sender.announce_retrying::<S, _, _>(4, |seed| S::announce(meta, seed))
    /// # }
    /// ```
    ///
    /// # Why a combinator rather than documentation
    ///
    /// The loop is four lines and every caller has to write the same four, correctly, including
    /// the part that is easy to get wrong: **the index must advance on rejection**, which means
    /// the seed must be drawn inside the loop and not before it. A caller who hoists the draw
    /// retries the same rejected index for ever, which is precisely the reuse §5 exists to
    /// forbid — and it is the natural way to write it, because drawing once looks like the
    /// efficient choice.
    ///
    /// `tries` is bounded rather than unbounded because a permanently unusable meta-address must
    /// terminate. Four is generous: schemeId 3's rejection probability is about 2⁻¹²⁸ per draw,
    /// so more than one rejection in a row is evidence of a defect and not of luck.
    ///
    /// # Errors
    ///
    /// Whatever `attempt` returns other than [`Error::SeedRejected`];
    /// [`Error::CounterExhausted`] if the index runs out; [`Error::SeedRejected`] if `tries`
    /// attempts were all rejected, which is a signal to stop and look rather than to keep going.
    pub fn announce_retrying<S, T, F>(&mut self, tries: u32, mut attempt: F) -> Result<T, Error>
    where
        S: StealthScheme,
        F: FnMut(&[u8]) -> Result<T, Error>,
    {
        for _ in 0..tries.max(1) {
            // INSIDE the loop. Drawing before it is the defect this function exists to prevent.
            let seed = self.draw_seed::<S>()?;
            match attempt(&seed) {
                Err(Error::SeedRejected) => continue,
                other => return other,
            }
        }
        Err(Error::SeedRejected)
    }

    /// The counter-advancing draw, without the trait bound.
    ///
    /// Exists so this crate's own tests can exercise §5 without depending on a scheme crate:
    /// `pqsa-core` sits below all of them, so a test needing a real [`StealthScheme`] would
    /// have to invert the dependency graph or duplicate the derivation — and a duplicated
    /// derivation is how the two halves of §5 came to disagree in the first place.
    fn draw(&mut self, scheme_id: u64, rung: &str, n: usize) -> Result<Vec<u8>, Error> {
        let i = self._counter;
        // Exhaustion is an error, never a wrap. A wrapped counter reuses index 0, and index
        // reuse repeats the stealth address — the failure §5 exists to prevent — so failing
        // loudly is the only acceptable behaviour at the boundary.
        self._counter = i.checked_add(1).ok_or(Error::CounterExhausted)?;
        Ok(announce_seed(
            &self._master,
            scheme_id,
            rung.as_bytes(),
            i,
            n,
        ))
    }

    /// Draw the next announce seed for a scheme family this crate cannot name by trait.
    ///
    /// **A HAZARDOUS low-level door, and public only because it has to be.**
    /// [`Self::draw_seed`] is the front door for [`StealthScheme`] rungs. The channel rungs
    /// live in a crate above this one and are deliberately not `StealthScheme` — their
    /// announce is a channel opening with retained state, not a per-payment announcement —
    /// so their crate wraps this with its own typed front door, and THAT wrapper is the
    /// call an integrator makes. What this door does not and cannot check: the three values
    /// are free text and numbers, a wrong `rung` string or width derives a different seed
    /// stream *silently*, and every call advances the shared index whether or not the seed
    /// is used — the typed prevention the wrappers claim is a convention here, not a
    /// property. **Take the three values off a scheme type's constants, or do not call
    /// this.**
    ///
    /// # Errors
    ///
    /// [`Error::CounterExhausted`] when the index space is spent.
    pub fn draw_seed_untyped(
        &mut self,
        scheme_id: u64,
        rung: &str,
        n: usize,
    ) -> Result<Vec<u8>, Error> {
        self.draw(scheme_id, rung, n)
    }

    #[cfg(test)]
    fn draw_seed_for(&mut self, scheme_id: u64, rung: &str, n: usize) -> Vec<u8> {
        self.draw(scheme_id, rung, n)
            .expect("the counter is not exhausted")
    }
}

/// Reject a keygen seed that would hand spending authority to a scanner.
///
/// # The rule, and why it is not the obvious one
///
/// §2.1 requires scanning **the delegated object as a whole** at every 32-byte offset, not
/// each of its fields separately. For schemeId 3 the delegated object is `viewing_ec ‖ dk` —
/// 96 bytes, so 65 window positions, of which per-field scanning covers 34. The 31 straddling
/// positions can place the spending seed verbatim in bytes handed to a scanning service and
/// pass a per-field check.
///
/// # Why it is public here rather than private to a rung
///
/// Because upstream it is `pub(crate)` in a crate that schemeId 6's does not depend on, so
/// that rung cannot reach it. One guard, one place, reachable by every rung.
///
/// # The signature takes ONE slice, not a list of fields, and that is the point
///
/// `delegated: &[&[u8]]` — a list of the fields making up the delegated object — would
/// **steer a caller into
/// exactly the defect the function exists to prevent.** Given a list, the obvious
/// implementation scans each element; the obvious *test* passes; and the 31 straddling
/// offsets are missed. A guard whose API invites the wrong implementation is worse than no
/// guard, because it also tells the reader the question has been handled.
///
/// So the caller concatenates first, and this takes the result. Concatenation is the caller's
/// job because only the caller knows the field order that goes on the wire, and the order is
/// what determines which offsets straddle.
///
/// # Errors
///
/// [`Error::SpendingKeyDelegated`] if any 32-byte window of `delegated` equals
/// `spending_seed`. There are `delegated.len() - 31` windows: 33 for a 64-byte `dk`, and
/// **65** for a 96-byte `viewing_ec ‖ dk`, not the 34 a per-field scan reaches.
pub fn reject_if_spending_key_is_delegated(
    spending_seed: &Bytes32,
    delegated: &[u8],
) -> Result<(), Error> {
    // EVERY 32-byte window, including the ones that straddle the boundary between the fields
    // the caller concatenated. `windows` yields exactly `len - 31` of them, which is what
    // `delegation_window_count` states and what a per-field scan misses 31 of.
    for window in delegated.windows(32) {
        if window == spending_seed.as_slice() {
            return Err(Error::SpendingKeyDelegated);
        }
    }
    Ok(())
}

/// §5's announce-seed derivation, shared by every rung.
///
/// ```text
/// seed_i = SHAKE256(DS || master(32) || u64be(i)
///                   || u64be(schemeId) || u64be(|rung|) || rung
///                   || u64be(|kem_id|) || kem_id, n)
/// ```
///
/// **The field order is load-bearing and every integer is eight bytes big-endian.** `i` sits
/// immediately after `master`, not at the end — an easy transposition to make, so `V6-05`
/// pins the order: a wrong one yields a well-formed seed
/// that no conforming implementation reproduces.
///
/// `kem_id` is **structural** — `u64be(|name|) || name`, so a wrapper embeds the identifier of
/// what it wraps rather than replacing it. Binding the rung alone is not enough: the same rung
/// over two KEMs is two different things that must not share a seed stream.
fn announce_seed(master: &Bytes32, scheme_id: u64, rung: &[u8], i: u64, n: usize) -> Vec<u8> {
    let kem_id = kem_id(KEM_NAME);
    let mut input = Vec::with_capacity(DS_SENDER.len() + 32 + 8 * 4 + rung.len() + kem_id.len());
    input.extend_from_slice(DS_SENDER);
    input.extend_from_slice(master);
    input.extend_from_slice(&i.to_be_bytes());
    input.extend_from_slice(&scheme_id.to_be_bytes());
    input.extend_from_slice(&(rung.len() as u64).to_be_bytes());
    input.extend_from_slice(rung);
    input.extend_from_slice(&(kem_id.len() as u64).to_be_bytes());
    input.extend_from_slice(&kem_id);
    let mut out = vec![0u8; n];
    let mut reader =
        <Shake256 as ExtendableOutput>::finalize_xof(Shake256::default().chain(&input));
    reader.read(&mut out);
    out
}

/// §5's `kem_id` for a bare KEM: `u64be(|name|) || name`. 18 bytes for `"ML-KEM-768"`.
fn kem_id(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + name.len());
    out.extend_from_slice(&(name.len() as u64).to_be_bytes());
    out.extend_from_slice(name);
    out
}

/// The number of 32-byte windows in a delegated object of `len` bytes.
///
/// Exposed so a conformance test can assert the count rather than trust it, because the count
/// is the whole difference between the correct scan and the one that ships the spending key:
/// `len - 32 + 1`, never `len / 32`. Returns 0 for `len < 32`, where there is no window at all
/// and a loop written as `0..=len - 32` on unsigned arithmetic would panic instead.
#[must_use]
pub const fn delegation_window_count(len: usize) -> usize {
    if len < 32 { 0 } else { len - 31 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal rung, so `draw_seed` can be exercised without depending on a scheme crate.
    ///
    /// It carries §5's canonical name for schemeId 2, because the NAME is bound into the
    /// derivation: two rungs sharing a `schemeId` and differing only in name must produce
    /// different seeds, and that is exactly what the three schemeId 6 levels need.
    struct Rung2;

    impl Rung2 {
        const SCHEME_ID: u64 = 2;
        const NAME: &'static str = "schemeId 2 (direct KEM)";
        const ANNOUNCE_SEED_BYTES: usize = 32;
    }

    fn seed(scheme_id: u64, rung: &str, i: u64, n: usize) -> Vec<u8> {
        let master: Bytes32 = [0xA5; 32];
        announce_seed(&master, scheme_id, rung.as_bytes(), i, n)
    }

    /// `V6-05`, from `vectors/section-5.json`, which was committed before this code existed.
    ///
    /// The three values are the ones a conforming sender draws. They are written out here
    /// rather than read from the file on purpose: this crate has no JSON dependency, and
    /// the conformance runner is what checks the whole committed set where a tree carries
    /// one — named rather than pathed, since this crate ships into trees that carry the
    /// fixtures without it. What this test buys is that `pqsa-core` alone cannot regress the
    /// derivation.
    #[test]
    fn announce_seed_matches_v6_05() {
        assert_eq!(
            hexlify(&seed(
                Rung2::SCHEME_ID,
                Rung2::NAME,
                0,
                Rung2::ANNOUNCE_SEED_BYTES
            )),
            "e5764131fba56a8f9c468cb223447a3a82aa712d6307ec1bdc43ec8d521e8d83",
            "schemeId 2, index 0"
        );
        assert_eq!(
            hexlify(&seed(
                Rung2::SCHEME_ID,
                Rung2::NAME,
                1,
                Rung2::ANNOUNCE_SEED_BYTES
            )),
            "41dc0bdd28960bc71f01faf1fce12cb3299f01dbb3be8f5da2d99bdcfc79a3df",
            "schemeId 2, index 1 -- a different index MUST give a different seed"
        );
        assert_eq!(
            hexlify(&seed(3, "schemeId 3 (direct KEM, hybrid)", 0, 64)),
            "69749ba9431b43fb3b501df75a572033fe667334d99507e15bdd410da704a83219c89823544fb1e7\
             f7896471dde6ba00dd508f8dfe22d79be7559b95d05c6a61"
                .replace(' ', ""),
            "schemeId 3 draws 64 bytes: ephemeral_seed(32) || encap_seed(32)"
        );
    }

    /// V6-05's `wrong` column: the transposition this test exists to catch.
    ///
    /// The index appended last instead of placed after `master` yields a well-formed 32-byte
    /// seed that no conforming implementation reproduces. Asserting the WRONG value is not
    /// produced is weaker than asserting the right one is; both are here because the wrong
    /// value is what the generator emitted for a day, so a regression to it is a real path.
    #[test]
    fn the_index_is_not_appended_last() {
        let wrong = "c16df0c3b3391be833173fe20b7aab90665a5d9ba2c3f4f15b2e59b624035c1c";
        let got = hexlify(&seed(Rung2::SCHEME_ID, Rung2::NAME, 0, 32));
        assert_ne!(
            got, wrong,
            "the index must sit immediately after master, not at the end"
        );
    }

    /// `kem_id` is `u64be(|name|) || name` — 18 bytes for `"ML-KEM-768"`, per §5.
    #[test]
    fn kem_id_is_length_prefixed_and_18_bytes() {
        let id = kem_id(KEM_NAME);
        assert_eq!(id.len(), 18);
        assert_eq!(hexlify(&id), "000000000000000a4d4c2d4b454d2d373638");
        assert_eq!(
            &id[..8],
            &10u64.to_be_bytes(),
            "the prefix is u64be, not a single byte"
        );
    }

    /// §2.1's scan is over the WHOLE delegated object, so the count is `len - 31`.
    ///
    /// 33 windows for a 64-byte `dk`, and **65** for a 96-byte `viewing_ec || dk` — not the 34
    /// a per-field scan reaches. The 31 straddling positions are the defect.
    #[test]
    fn delegation_window_counts() {
        assert_eq!(delegation_window_count(64), 33);
        assert_eq!(delegation_window_count(96), 65);
        assert_eq!(delegation_window_count(32), 1);
        assert_eq!(
            delegation_window_count(31),
            0,
            "no window fits, and must not underflow"
        );
        assert_eq!(delegation_window_count(0), 0);
    }

    /// The guard fires on a straddling offset, which is the whole point of scanning the
    /// concatenation. Offset 17 of a 96-byte object lies across the 32-byte boundary.
    #[test]
    fn the_guard_catches_a_straddling_offset() {
        let spending: Bytes32 = [0x11; 32];
        for offset in [0usize, 1, 16, 17, 31, 32, 63, 64] {
            let mut delegated = vec![0x44u8; 96];
            delegated[offset..offset + 32].copy_from_slice(&spending);
            assert!(
                matches!(
                    reject_if_spending_key_is_delegated(&spending, &delegated),
                    Err(Error::SpendingKeyDelegated)
                ),
                "offset {offset} must be rejected; a per-field scan misses 17 through 31"
            );
        }
        let clean = vec![0x44u8; 96];
        assert!(reject_if_spending_key_is_delegated(&spending, &clean).is_ok());
    }

    /// `resume(m, 42)` means 42 is the next UNUSED index, so drawing consumes it and the
    /// counter becomes 43. Off by one the other way repeats an index after every restart.
    #[test]
    fn the_counter_is_next_unused() {
        let mut st = SenderState::resume([0xA5; 32], 0);
        assert_eq!(st.counter(), 0);
        let first = st.draw_seed_for(2, "schemeId 2 (direct KEM)", 32);
        assert_eq!(st.counter(), 1, "drawing consumes the index it was given");
        let second = st.draw_seed_for(2, "schemeId 2 (direct KEM)", 32);
        assert_ne!(first, second, "two draws must not give one seed");
        assert_eq!(
            hexlify(&first),
            "e5764131fba56a8f9c468cb223447a3a82aa712d6307ec1bdc43ec8d521e8d83",
            "the first draw is index 0, matching V6-05"
        );
    }

    /// A rung's NAME is bound in, so two rungs sharing a `schemeId` get different seeds.
    /// Without this the three schemeId 6 levels would draw the byte-identical KEM message.
    #[test]
    fn the_rung_name_is_bound_not_only_the_id() {
        let a = seed(6, "schemeId 6 (Spirit, level 2)", 0, 32);
        let b = seed(6, "schemeId 6 (Spirit, level 3)", 0, 32);
        assert_ne!(a, b);
    }

    fn hexlify(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// §5's rejection loop advances the index, and does so because the draw is inside the loop.
    ///
    /// The rejection cannot be reached by choosing inputs — that is what `V6-03` records — so the
    /// `attempt` closure stands in for it: it rejects the first two seeds and accepts the third,
    /// and the test asserts the three seeds were DIFFERENT. That is the property §5 actually
    /// requires, and the one a caller who hoists the draw out of the loop breaks while still
    /// appearing to retry.
    #[test]
    fn a_rejected_seed_advances_the_index_and_is_never_reused() {
        struct Fake;
        impl StealthScheme for Fake {
            const SCHEME_ID: u64 = 2;
            const NAME: &'static str = "fake";
            const KEYGEN_SEED_BYTES: usize = 96;
            const ANNOUNCE_SEED_BYTES: usize = 32;
            type Meta = ();
            type Master = ();
            type Tracking = ();
            type Announcement = ();
            type Match = ();
            type Scanner = ();
            type SpendKey = Bytes32;
            fn keygen(_: &[u8]) -> Result<Keys<Self>, Error> {
                Err(Error::Malformed)
            }
            fn announce(_: &(), _: &[u8]) -> Result<(), Error> {
                Err(Error::Malformed)
            }
            fn bind(_: &(), _: &()) -> Result<(), Error> {
                Err(Error::Malformed)
            }
            fn scan(_: &(), _: &()) -> Option<()> {
                None
            }
            fn spend_key(_: &(), _: &()) -> Result<Bytes32, Error> {
                Err(Error::Malformed)
            }
            fn match_address(_: &()) -> [u8; 20] {
                [0; 20]
            }
            fn meta_to_bytes(_: &()) -> Vec<u8> {
                Vec::new()
            }
            fn meta_from_bytes(_: &[u8]) -> Option<()> {
                None
            }
            fn announcement_to_bytes(_: &()) -> ([u8; 20], Vec<u8>, Vec<u8>) {
                ([0; 20], Vec::new(), Vec::new())
            }
            fn announcement_from_bytes(_: &[u8; 20], _: &[u8], _: &[u8]) -> Option<()> {
                None
            }
        }

        let mut state = SenderState::resume([0x11; 32], 0);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let out = state.announce_retrying::<Fake, _, _>(4, |seed| {
            seen.push(seed.to_vec());
            if seen.len() < 3 {
                Err(Error::SeedRejected)
            } else {
                Ok(seen.len())
            }
        });
        assert_eq!(out, Ok(3), "the third attempt is accepted");
        assert_eq!(seen.len(), 3);
        assert_ne!(seen[0], seen[1], "a rejected index MUST NOT be retried");
        assert_ne!(seen[1], seen[2]);
        assert_eq!(
            state.counter(),
            3,
            "and the index advanced once per attempt"
        );

        // An error that is NOT a rejection stops immediately: retrying a broken meta-address
        // for ever is the failure the bound and this branch exist to prevent.
        let mut state = SenderState::resume([0x11; 32], 0);
        let mut calls = 0;
        let out = state.announce_retrying::<Fake, usize, _>(4, |_| {
            calls += 1;
            Err(Error::Malformed)
        });
        assert_eq!(out, Err(Error::Malformed));
        assert_eq!(calls, 1, "a non-rejection error is not retried");

        // And exhausting the tries reports the rejection rather than looping.
        let mut state = SenderState::resume([0x11; 32], 0);
        let out = state.announce_retrying::<Fake, usize, _>(2, |_| Err(Error::SeedRejected));
        assert_eq!(out, Err(Error::SeedRejected));
        assert_eq!(state.counter(), 2, "and it drew a fresh index for each try");
    }

    const MASTER: [u8; 32] = [0xa5; 32];
    const RUNG_2: &[u8] = b"schemeId 2 (direct KEM)";
    const RUNG_3: &[u8] = b"schemeId 3 (direct KEM, hybrid)";

    /// `V6-01`, both rungs, against the committed fixture.
    ///
    /// The bytes are transcribed from `vectors/section-5.json`, which is the thing this is
    /// checked against. That makes this a *second implementation* of §5's derivation agreeing
    /// with the Python that generated the fixture — the two are independent in the part that
    /// matters, since `tools/vecprim.py` hand-rolls HKDF over `hmac` and this calls RustCrypto's.
    #[test]
    fn v6_01_the_keygen_seed_derivation() {
        let s2 = keygen_seed(&MASTER, 2, RUNG_2, 0, 96).unwrap();
        assert_eq!(
            hexlify(&s2),
            "0b696cffccb35f947f0a245c65c563ceeefc415406534ca37da186bcca9ea1fb             fd491387b7599e89f6d34cda416fc5378734521ced761fecea8e44b0bd7f5857             66ce9eaf5eb476f87034f1edc214b73578dde25b26457ebc3308adddabf9c23d"
                .replace(' ', "")
        );
        let s3 = keygen_seed(&MASTER, 3, RUNG_3, 0, 128).unwrap();
        assert_eq!(
            hexlify(&s3),
            "42bd3c7fd29ccc42e9f8a655995fbfd4699b7f53daf62c9142f591908ccbb03d             a9c53cfc18d95955ed3222013bce036a8e6d2fe790d614f3ab86b8cb187c4b89             447412f0c3d2978d6b1c1b1830907c82c214f889af40478f2b84efe79e9d15e1             a4cb056acf428e47138a6520c4494ec7b3c244082e7d31f44ad1f24327a2fd6c"
                .replace(' ', "")
        );
    }

    /// `V6-01`'s `wrong` column, which is the half that makes the row a test rather than a
    /// transcription. Each of these is a plausible misreading of §5 and each produces a
    /// well-formed seed that recovers keys the recipient never had.
    #[test]
    fn v6_01_the_named_wrong_answers_are_wrong() {
        let right = keygen_seed(&MASTER, 2, RUNG_2, 0, 96).unwrap();

        // "L = 32 always", instead of the scheme's seed length -- and the interesting part is
        // that this is NOT a different string. HKDF-Expand is counter-based, so a shorter L is a
        // PREFIX of a longer one for the same info. **This error is undetectable by comparing
        // content and is caught only by the seed-length check.**
        //
        // A `fixed_L_32` generated with a shortened rung name as well would change two
        // variables at once and look like a distinguishable wrong answer — which is what
        // writing this test against the fixture is for.
        let fixed_l = keygen_seed(&MASTER, 2, RUNG_2, 0, 32).unwrap();
        assert_eq!(
            fixed_l[..],
            right[..32],
            "a short L is a prefix, not a different seed"
        );
        assert_ne!(fixed_l.len(), right.len(), "so LENGTH is the entire signal");

        // The shortened name, which IS a different string -- and shares no prefix with the
        // right answer, because `info` changed rather than `L`.
        let short_name = keygen_seed(&MASTER, 2, b"schemeId 2", 0, 96).unwrap();
        assert_eq!(
            hexlify(&short_name),
            "6ad22ee3213dcb10b39c779fa24b046ff5f75e8692602bae70013ff7b89476c2\
             752640137807c875979462359873439a0863828b60f234328f404f02cbc3ccfa\
             f2ad9f4525957399272dc0e9908ab189b375edac21b4055d4165e99492a83d50"
                .replace(' ', "")
        );
        assert_ne!(right, short_name);

        // The rung name omitted from `info` altogether.
        let no_rung = keygen_seed(&MASTER, 2, b"", 0, 96).unwrap();
        assert_eq!(
            hexlify(&no_rung),
            "005e8c19ecb81e79d6ec2aa462411502f50ddd67f6f6959052e3ac3401e3d8f3             0152d1f09f669a92d07494269843c1359d70ad9ca32a85c0bfb2cf1c9602f926             53deac9a25b9c639a8ab5bf00918c8e824a14b2462525cf0c130ba7bb0aa140a"
                .replace(' ', "")
        );
        assert_ne!(right, no_rung);
    }

    /// `V6-04`: a rejection advances the index of that pair and **no other**.
    ///
    /// The trigger cannot be reached by choosing inputs — it needs a seed injected past the
    /// derivation — so what is pinned is the consequence, which is the half the superseded rule
    /// got wrong: it drew a fresh `keygen_master`, which would move every other rung's seeds too.
    #[test]
    fn v6_04_a_rejection_advances_one_index_and_leaves_the_others() {
        let a0 = keygen_seed(&MASTER, 2, RUNG_2, 0, 96).unwrap();
        let a1 = keygen_seed(&MASTER, 2, RUNG_2, 1, 96).unwrap();
        let b0 = keygen_seed(&MASTER, 3, RUNG_3, 0, 128).unwrap();

        assert_eq!(
            hexlify(&a1),
            "3f0a4062a1e8ccf1fa6350cacf744d3e64f788b596b6c9dd427011778bfa2333             687f0894a55bd6f7a3740e0a44cb25689c1911beba5bc1ee705b0ee578435e2d             c30dc71a4af4635316177d648cc5d8d2bd29206645d2aca2ca668b3469baea06"
                .replace(' ', "")
        );
        assert_ne!(a0, a1, "the index moved the seed");
        // The point of the row: rung B is untouched by rung A's rejection, which is only true
        // because `keygen_master` is unchanged and `j` is per (schemeId, rung).
        assert_eq!(b0, keygen_seed(&MASTER, 3, RUNG_3, 0, 128).unwrap());
        assert_ne!(b0[..96], a1[..], "and the two rungs never collide");
    }

    /// RFC 5869's absent salt is HashLen zero bytes, and the code writes `None`. Asserted rather
    /// than trusted, because §5 now makes the equivalence normative and a reader checking the
    /// document against the code should find the claim tested somewhere.
    #[test]
    fn keygen_seed_matches_an_explicit_zero_salt() {
        let info_free = keygen_seed(&MASTER, 2, RUNG_2, 0, 96).unwrap();
        let explicit = {
            let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&[0u8; 32]), &MASTER);
            let mut info = Vec::new();
            info.extend_from_slice(DS_KEYGEN);
            info.extend_from_slice(&2u64.to_be_bytes());
            info.extend_from_slice(&(RUNG_2.len() as u64).to_be_bytes());
            info.extend_from_slice(RUNG_2);
            info.extend_from_slice(&0u64.to_be_bytes());
            let mut out = vec![0u8; 96];
            hk.expand(&info, &mut out).unwrap();
            out
        };
        assert_eq!(info_free, explicit);
    }

    /// Lengths and bounds. `L = 0` and `L > 255 * 32` are both `Malformed`, and a 31- or
    /// 33-byte master is too — §5 fixes it at 32.
    #[test]
    fn keygen_seed_rejects_out_of_range_inputs() {
        assert!(matches!(
            keygen_seed(&MASTER, 2, RUNG_2, 0, 0),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            keygen_seed(&MASTER, 2, RUNG_2, 0, 255 * 32 + 1),
            Err(Error::Malformed)
        ));
        assert!(keygen_seed(&MASTER, 2, RUNG_2, 0, 255 * 32).is_ok());
        assert!(matches!(
            keygen_seed(&[0xa5; 31], 2, RUNG_2, 0, 96),
            Err(Error::Malformed)
        ));
        assert!(matches!(
            keygen_seed(&[0xa5; 33], 2, RUNG_2, 0, 96),
            Err(Error::Malformed)
        ));
    }
}
