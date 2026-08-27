//! Shared scheme interface: [`StealthScheme`], errors, §5 seed derivation, the delegation guard.
//!
//! Protocol: `spec/ERC-VVVV-schemeid3.md` (§1 vocabulary, §5 seeds). This crate does not
//! implement a rung.
//!
//! [`SenderState`] derives announce seeds and increments an index. Reusing a seed repeats
//! the KEM ciphertext and the stealth address. [`StealthScheme::announce`] still takes raw
//! `&[u8]`; using [`SenderState`] is convention, not enforced.

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// 32-byte array (seed, scalar, shared secret, or hash).
pub type Bytes32 = [u8; 32];

/// §5's domain separator for the sender-entropy derivation.
const DS_SENDER: &[u8] = b"pq-stealth/sender-seed/v1";

/// §5's canonical KEM name for the deployed path. `kem_id` length-prefixes it.
const KEM_NAME: &[u8] = b"ML-KEM-768";

/// View-tag width in bytes. §1.
///
/// Compared in full. ML-KEM implicit rejection returns a pseudorandom secret (no error) for
/// a foreign ciphertext, so this tag is how a scanner decides "ours". At 1 byte, 1 in 256
/// foreign announcements look like hits and force a chain-state query (§9).
pub const VIEW_TAG_BYTES: usize = 8;

/// Recoverable failure. A scan miss is [`Option::None`], because `announce()` is
/// permissionless and an error path would be a DoS (§2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wrong length, tag, or field layout. §1.
    Malformed,
    /// Scalar reduction hit §1's retry bound with no valid scalar.
    NoValidScalar,
    /// A 32-byte window of the delegated object equals the spending seed. §2.1.
    SpendingKeyDelegated,
    /// Sender counter would wrap. Wrapping reuses a seed. §5.
    CounterExhausted,
    /// KEM rejected a malformed key or ciphertext. [`StealthScheme::scan`] maps this to [`None`].
    Kem,
    /// This announce seed is unusable; draw the next index. The only error a sender should retry.
    ///
    /// [`Self::NoValidScalar`] also comes from keygen and from offset reduction. Looping on
    /// that would retry a permanently broken meta-address. schemeId 3 returns this when the
    /// first 32 bytes of the announce seed are not a valid secp256k1 scalar (~2⁻¹²⁸ per draw).
    SeedRejected,
    /// Tracking key does not match the meta-address: recomputed `ek` (and on schemeId 3 the
    /// viewing point) differs from the registry. §1. A bit-flipped `(d, z)` expands to a
    /// consistent keypair for a different key, so FIPS 203's own checks pass and only this
    /// comparison notices. A stranger cannot trigger it.
    TrackingKeyMismatch,
    /// `master` and `Match` are well-formed but the spending scalar does not control
    /// the match's stealth address. §2.6.
    MasterKeyMismatch,
    /// Unused in this tree.
    AddressMappingOpen,
}

/// [`StealthScheme::keygen`] output: `(Meta, Master, Tracking)` in that order.
pub type Keys<S> = (
    <S as StealthScheme>::Meta,
    <S as StealthScheme>::Master,
    <S as StealthScheme>::Tracking,
);

/// One stealth-address scheme. Vocabulary §1; wire and registry §6.
///
/// Associated types vary by scheme. Keygen is deterministic in its seed; nothing here draws
/// randomness. The `SCHEME_ID` values in this tree are proposals, not reserved with ERC-5564.
pub trait StealthScheme {
    /// ERC-5564 `schemeId` this scheme claims. Not reserved.
    const SCHEME_ID: u64;

    /// Stable protocol/domain-separation name, also used in vectors and logs. Never parsed,
    /// but changing it changes the announce-seed stream.
    const NAME: &'static str;

    /// Keygen seed length. Other lengths are [`Error::Malformed`].
    const KEYGEN_SEED_BYTES: usize;

    /// Announce seed length. §5.
    const ANNOUNCE_SEED_BYTES: usize;

    /// Published via ERC-6538.
    type Meta;
    /// Recipient spending secret. Never delegated.
    type Master;
    /// May be handed to a scanning service. §2.1. A delegated scanner sees the whole payment graph (§9).
    type Tracking;
    /// Published via ERC-5564 `announce()`.
    type Announcement;
    /// Successful scan; input to [`Self::spend_key`].
    type Match;
    /// Output of [`Self::bind`]: tracking checked against a meta-address, plus values
    /// [`Self::scan`] reuses (so `scan` does not rerun ML-KEM keygen per event).
    type Scanner;
    /// One-time spending key. secp256k1 scalar on schemeIds 2 and 3.
    type SpendKey;

    /// Derive `(meta, master, tracking)` from `seed` of length [`Self::KEYGEN_SEED_BYTES`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a wrong length, [`Error::NoValidScalar`] after §1's retry
    /// bound, [`Error::SpendingKeyDelegated`] if §2.1's guard fires.
    fn keygen(seed: &[u8]) -> Result<Keys<Self>, Error>
    where
        Self: Sized;

    /// Announce a payment to `meta` using `seed`.
    ///
    /// `seed` should come from [`SenderState::draw_seed`]. This method does not enforce
    /// that: the same seed twice yields the same announcement and stealth address.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a meta-address this rung does not accept, [`Error::Kem`] on
    /// encapsulation failure, [`Error::SeedRejected`] if this seed's derived material is
    /// unusable (retry with the next index).
    fn announce(meta: &Self::Meta, seed: &[u8]) -> Result<Self::Announcement, Error>;

    /// Check `tracking` against `meta` and cache what [`Self::scan`] reuses.
    ///
    /// Recomputes `ek` from `(d, z)` and compares it to the registered key; schemeId 3 also
    /// compares the viewing point. A bit-flipped tracking seed is otherwise silent.
    ///
    /// # Errors
    ///
    /// [`Error::TrackingKeyMismatch`] if a delegated component does not match the registry.
    /// [`Error::Malformed`] if the shapes are not this scheme's.
    fn bind(tracking: &Self::Tracking, meta: &Self::Meta) -> Result<Self::Scanner, Error>;

    /// Whether this announcement is ours.
    ///
    /// Returns [`Option`], never [`Result`]. Malformed, foreign, and KEM-failure cases are
    /// all [`None`] (`announce()` is permissionless, §2.5).
    ///
    /// `scanner` comes from [`Self::bind`]. Stateless: the same input always yields the same
    /// match. Deduplicating replays (same stealth address twice) is the caller's job and
    /// must persist across batches (§2.5).
    fn scan(scanner: &Self::Scanner, ann: &Self::Announcement) -> Option<Self::Match>;

    /// One-time spending key for a match.
    ///
    /// Call only after [`Self::scan`] returned [`Some`] for this announcement. SchemeIds 2
    /// and 3 return [`Error::MasterKeyMismatch`] if `master`'s spending scalar does not
    /// control the match's stealth address (§2.6).
    ///
    /// # Errors
    ///
    /// [`Error::NoValidScalar`] if the derived scalar is invalid;
    /// [`Error::MasterKeyMismatch`] if the key would not spend at the match address.
    fn spend_key(master: &Self::Master, m: &Self::Match) -> Result<Self::SpendKey, Error>;

    /// Stealth address of this match. For generic code that cannot read [`Self::Match`]
    /// fields; §2.8 compares it to the announced address.
    fn match_address(m: &Self::Match) -> [u8; 20];

    /// Serialise a meta-address for ERC-6538 `registerKeys`. §6.
    fn meta_to_bytes(meta: &Self::Meta) -> Vec<u8>;

    /// Parse a registry blob. [`None`] if it is not this scheme's.
    fn meta_from_bytes(bytes: &[u8]) -> Option<Self::Meta>;

    /// ERC-5564 payload: `(stealthAddress, ephemeralPubKey, metadata)`.
    ///
    /// The address is the one this announcement's payment derives (§2.4). `schemeId` is a
    /// separate argument of `announce()` and is not part of this triple.
    fn announcement_to_bytes(ann: &Self::Announcement) -> ([u8; 20], Vec<u8>, Vec<u8>);

    /// Parse an ERC-5564 event. [`None`] if it is not this scheme's.
    ///
    /// `stealth_address` is required. `[0u8; 20]` is a valid Ethereum address, so it cannot
    /// stand in for "missing"; a parser that filled zeros would make §2.8 reject every payment.
    fn announcement_from_bytes(
        stealth_address: &[u8; 20],
        epk: &[u8],
        metadata: &[u8],
    ) -> Option<Self::Announcement>;
}

/// Spend key as bytes for a secp256k1 ECDSA signer.
pub trait ExportableSpendKey: StealthScheme {
    /// One-time spending key as bytes.
    fn spend_key_bytes(k: &Self::SpendKey) -> &[u8];
}

/// §5's domain separator for the keygen-seed derivation. Distinct from the announce seed's.
const DS_KEYGEN: &[u8] = b"pq-stealth/keygen/v1";

/// §5 keygen-seed derivation from a 32-byte master:
///
/// ```text
/// HKDF-SHA256(
///     ikm  = keygen_master,
///     salt = absent,          // RFC 5869: HashLen zero bytes, not "skip Extract"
///     info = "pq-stealth/keygen/v1" ‖ u64be(schemeId) ‖ u64be(|rung|) ‖ rung ‖ u64be(j),
///     L    = KEYGEN_SEED_BYTES)
/// ```
///
/// Running Expand alone (treating `ikm` as a PRK) yields a different seed. `j` starts at 0
/// and advances on rejection. This function only derives; the caller stores `j`.
///
/// # Errors
///
/// [`Error::Malformed`] if `master` is not 32 bytes, or if `length` is 0 or > 255 × 32.
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

    // RFC 5869 absent salt = HashLen zeros. `None` and `Some(&[0u8; 32])` agree; a test pins it.
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, master);
    let mut out = vec![0u8; length];
    hk.expand(&info, &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// Per-sender announce-seed state: master and next unused index. §5.
///
/// Persist both. Losing the counter and continuing reuses an index, which repeats a stealth
/// address. [`StealthScheme::announce`] still accepts any `&[u8]`. Two `SenderState` values
/// resumed at the same counter also collide.
pub struct SenderState {
    _master: Bytes32,
    _counter: u64,
}

impl SenderState {
    /// Resume from a persisted pair. `counter` is the **next unused** index, not the last used.
    ///
    /// `resume(m, 42)` consumes 42 on the next [`Self::draw_seed`]. Passing the last-used
    /// index after restart repeats a seed. There is no `new()`: a fresh sender is
    /// `resume(master, 0)`.
    #[must_use]
    pub fn resume(master: Bytes32, counter: u64) -> Self {
        Self {
            _master: master,
            _counter: counter,
        }
    }

    /// The next unused index, to persist alongside `master`. Store this after every
    /// [`Self::draw_seed`], not the value passed to [`Self::resume`].
    #[must_use]
    pub fn counter(&self) -> u64 {
        self._counter
    }

    /// Draw the next announce seed for rung `S` and advance the counter.
    ///
    /// The seed binds both [`StealthScheme::SCHEME_ID`] and [`StealthScheme::NAME`].
    ///
    /// # Errors
    ///
    /// [`Error::CounterExhausted`] if the index would wrap.
    pub fn draw_seed<S: StealthScheme>(&mut self) -> Result<Vec<u8>, Error> {
        self.draw(S::SCHEME_ID, S::NAME, S::ANNOUNCE_SEED_BYTES)
    }

    /// Draw seeds until `attempt` accepts one. The draw is inside the loop so a rejection
    /// advances the index. Other errors stop immediately.
    ///
    /// ```no_run
    /// # use pqsa_core::{SenderState, StealthScheme, Error};
    /// # fn f<S: StealthScheme>(meta: &S::Meta, sender: &mut SenderState)
    /// #     -> Result<S::Announcement, Error> {
    /// sender.announce_retrying::<S, _, _>(4, |seed| S::announce(meta, seed))
    /// # }
    /// ```
    ///
    /// `tries == 0` is treated as 1 (`tries.max(1)`).
    ///
    /// # Errors
    ///
    /// [`Error::CounterExhausted`] if an index would wrap; [`Error::SeedRejected`] if every
    /// attempt rejects its seed; otherwise the first non-rejection error from `attempt`.
    pub fn announce_retrying<S, T, F>(&mut self, tries: u32, mut attempt: F) -> Result<T, Error>
    where
        S: StealthScheme,
        F: FnMut(&[u8]) -> Result<T, Error>,
    {
        for _ in 0..tries.max(1) {
            // Draw inside the loop: hoisting it retries the same rejected index.
            let seed = self.draw_seed::<S>()?;
            match attempt(&seed) {
                Err(Error::SeedRejected) => continue,
                other => return other,
            }
        }
        Err(Error::SeedRejected)
    }

    /// Counter-advancing draw without a [`StealthScheme`] bound (tests and [`Self::draw_seed_untyped`]).
    fn draw(&mut self, scheme_id: u64, rung: &str, n: usize) -> Result<Vec<u8>, Error> {
        let i = self._counter;
        // Do not wrap: a wrapped counter reuses index 0.
        self._counter = i.checked_add(1).ok_or(Error::CounterExhausted)?;
        Ok(announce_seed(
            &self._master,
            scheme_id,
            rung.as_bytes(),
            i,
            n,
        ))
    }

    /// Untyped draw. A wrong `rung` string or `n` silently selects a different seed stream
    /// and still advances the counter. Prefer [`Self::draw_seed`].
    ///
    /// # Errors
    ///
    /// [`Error::CounterExhausted`] if the index would wrap.
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

/// Reject a keygen seed that would put the spending scalar in the delegated object. §2.1.
///
/// Scan every 32-byte window of the **concatenated** delegated bytes, including windows that
/// straddle field boundaries. A per-field scan of schemeId 3's `viewing_ec ‖ dk` (96 B)
/// covers 34 positions; the full scan covers 65. The caller concatenates in wire order.
///
/// # Errors
///
/// [`Error::SpendingKeyDelegated`] if any window equals `spending_seed`.
pub fn reject_if_spending_key_is_delegated(
    spending_seed: &Bytes32,
    delegated: &[u8],
) -> Result<(), Error> {
    for window in delegated.windows(32) {
        if window == spending_seed.as_slice() {
            return Err(Error::SpendingKeyDelegated);
        }
    }
    Ok(())
}

/// §5 announce seed. Integers are u64be. `i` sits immediately after `master` (V6-05).
///
/// ```text
/// SHAKE256(DS || master(32) || u64be(i)
///          || u64be(schemeId) || u64be(|rung|) || rung
///          || u64be(|kem_id|) || kem_id, n)
/// ```
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

/// Number of 32-byte windows in `len` bytes: `len - 31`, or 0 if `len < 32`.
#[must_use]
pub const fn delegation_window_count(len: usize) -> usize {
    if len < 32 { 0 } else { len - 31 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in so §5 can be tested without a scheme crate. `NAME` is bound into the seed.
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

    /// V6-05 known answers (transcribed; this crate has no JSON dependency).
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

    /// V6-05: `i` after `master`, not appended last.
    #[test]
    fn the_index_is_not_appended_last() {
        let wrong = "c16df0c3b3391be833173fe20b7aab90665a5d9ba2c3f4f15b2e59b624035c1c";
        let got = hexlify(&seed(Rung2::SCHEME_ID, Rung2::NAME, 0, 32));
        assert_ne!(
            got, wrong,
            "the index must sit immediately after master, not at the end"
        );
    }

    /// `kem_id` is `u64be(|name|) || name` (18 bytes for `"ML-KEM-768"`). §5.
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

    /// Window count is `len - 31` (65 for 96 B, not 34).
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

    /// Guard catches windows that straddle the 32-byte field boundary (e.g. offset 17).
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

    /// `resume` takes the next unused index; drawing consumes it.
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

    /// `NAME` is bound in: two rungs with the same id must not share a seed stream.
    #[test]
    fn the_rung_name_is_bound_not_only_the_id() {
        let a = seed(6, "schemeId 6 (Spirit, level 2)", 0, 32);
        let b = seed(6, "schemeId 6 (Spirit, level 3)", 0, 32);
        assert_ne!(a, b);
    }

    fn hexlify(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Rejection advances the index; a non-rejection error stops; exhausting `tries` reports SeedRejected.
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

        // Non-rejection errors are not retried.
        let mut state = SenderState::resume([0x11; 32], 0);
        let mut calls = 0;
        let out = state.announce_retrying::<Fake, usize, _>(4, |_| {
            calls += 1;
            Err(Error::Malformed)
        });
        assert_eq!(out, Err(Error::Malformed));
        assert_eq!(calls, 1, "a non-rejection error is not retried");

        // Exhausting tries reports SeedRejected.
        let mut state = SenderState::resume([0x11; 32], 0);
        let out = state.announce_retrying::<Fake, usize, _>(2, |_| Err(Error::SeedRejected));
        assert_eq!(out, Err(Error::SeedRejected));
        assert_eq!(state.counter(), 2, "and it drew a fresh index for each try");
    }

    const MASTER: [u8; 32] = [0xa5; 32];
    const RUNG_2: &[u8] = b"schemeId 2 (direct KEM)";
    const RUNG_3: &[u8] = b"schemeId 3 (direct KEM, hybrid)";

    /// V6-01 known answers (RustCrypto HKDF vs the Python generator).
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

    /// V6-01: short L is a prefix; a shortened or omitted rung name is a different seed.
    #[test]
    fn v6_01_the_named_wrong_answers_are_wrong() {
        let right = keygen_seed(&MASTER, 2, RUNG_2, 0, 96).unwrap();

        // HKDF-Expand: shorter L is a prefix of longer L for the same info.
        let fixed_l = keygen_seed(&MASTER, 2, RUNG_2, 0, 32).unwrap();
        assert_eq!(
            fixed_l[..],
            right[..32],
            "a short L is a prefix, not a different seed"
        );
        assert_ne!(fixed_l.len(), right.len(), "so LENGTH is the entire signal");

        let short_name = keygen_seed(&MASTER, 2, b"schemeId 2", 0, 96).unwrap();
        assert_eq!(
            hexlify(&short_name),
            "6ad22ee3213dcb10b39c779fa24b046ff5f75e8692602bae70013ff7b89476c2\
             752640137807c875979462359873439a0863828b60f234328f404f02cbc3ccfa\
             f2ad9f4525957399272dc0e9908ab189b375edac21b4055d4165e99492a83d50"
                .replace(' ', "")
        );
        assert_ne!(right, short_name);

        let no_rung = keygen_seed(&MASTER, 2, b"", 0, 96).unwrap();
        assert_eq!(
            hexlify(&no_rung),
            "005e8c19ecb81e79d6ec2aa462411502f50ddd67f6f6959052e3ac3401e3d8f3             0152d1f09f669a92d07494269843c1359d70ad9ca32a85c0bfb2cf1c9602f926             53deac9a25b9c639a8ab5bf00918c8e824a14b2462525cf0c130ba7bb0aa140a"
                .replace(' ', "")
        );
        assert_ne!(right, no_rung);
    }

    /// V6-04: advancing `j` for one (schemeId, rung) pair leaves the others alone.
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
        assert_eq!(b0, keygen_seed(&MASTER, 3, RUNG_3, 0, 128).unwrap());
        assert_ne!(b0[..96], a1[..], "and the two rungs never collide");
    }

    /// `Hkdf::new(None, …)` equals `Some(&[0u8; 32])`.
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

    /// `L = 0`, `L > 255*32`, and a master other than 32 bytes are `Malformed`.
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
