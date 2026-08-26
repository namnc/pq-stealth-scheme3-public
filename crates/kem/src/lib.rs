//! The KEM behind a trait, and ML-KEM-768 as the only instantiation this ladder specifies.
//!
//! # Why a trait at all, when there is one KEM
//!
//! Not for pluggability. §1 fixes ML-KEM-768, and the specification puts a rung instantiated
//! over a different KEM outside itself — stated in §4 in a set that specifies the
//! post-quantum-spending rung, and in §1 alone otherwise. The trait exists for two narrower
//! reasons:
//!
//! - **The derandomised internal algorithms.** §1 requires encapsulation take its randomness
//!   as a parameter rather than drawing it, because §5's seeds are what make conformance
//!   vectors possible. FIPS 203 names those internal functions; a wrapper that hides them
//!   cannot be tested against a vector.
//! - **Naming the substitution.** The upstream KEM sits behind a trait with swappable
//!   implementations, so "any KEM
//!   instantiates this rung for free" — and nothing can enforce §4's rule as the code is
//!   structured. That is recorded rather than fixed. **A trait here does not make the
//!   substitution conforming**, and this paragraph is the whole of what stands between the
//!   two readings.
//!
//! # What this crate deliberately cannot do
//!
//! Draw randomness. Every entry point takes its seed.
//!
//! # Status
//!
//! **Implemented over RustCrypto's `ml-kem`**, against the committed conformance vectors.
//!
//! # Why that library and not another
//!
//! §1 requires the **derandomised internal algorithms** — `KeyGen_internal(d, z)` and
//! `Encaps_internal(ek, m)` — because three requirements are only satisfiable through them:
//! encapsulation deterministic in `m`, `m` derived rather than sampled per §5, and a 64-byte
//! `(d, z)` decapsulation key rather than the 2 400-byte expanded form. A library exposing
//! only FIPS 203's public interface would not do, and §1 says so as a cost to implementers
//! rather than leaving it to be discovered. `ml-kem` exposes `DecapsulationKey::from_seed` and
//! `encapsulate_deterministic`, which are exactly those two entry points.
//!
//! **Decapsulation is deliberately NOT constrained** by §1: `Decaps` draws no randomness and
//! returns no key, so mandating the internal form bought nothing and removed FIPS 203's own
//! input checks. This crate calls the ordinary `Decapsulate`.

use ml_kem::kem::Kem as MlKemTrait;
use ml_kem::{Decapsulate, KeyExport, MlKem768 as MlKem768Params, Seed};
use pqsa_core::{Bytes32, Error};

/// A key-encapsulation mechanism, derandomised.
///
/// Specification: §1. Sizes are re-derived from FIPS 203 by `tools/derive_sizes.py`, which is
/// the harness rule #54 requires — a figure with no committed generator is unfalsifiable.
pub trait Kem {
    /// The encapsulation key's length. 1 184 for ML-KEM-768: `384·k + 32` at `k = 3`.
    const EK_BYTES: usize;
    /// The ciphertext's length. 1 088 for ML-KEM-768: `32·(du·k + dv)` at `du = 10`, `dv = 4`.
    const CT_BYTES: usize;
    /// The keygen seed's length. 64 for ML-KEM-768 — the `(d, z)` pair.
    ///
    /// **Not the expanded decapsulation key**, which is 2 400 bytes. §2.1 delegates the
    /// 64-byte seed, and the difference is what makes a tracking key small enough to hand to a
    /// scanning service.
    const KEYGEN_SEED_BYTES: usize;
    /// The encapsulation seed's length. 32 for ML-KEM-768 — the message `m`.
    const ENCAP_SEED_BYTES: usize;

    /// Derive a keypair from `seed`, which MUST be [`Self::KEYGEN_SEED_BYTES`] long.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a wrong length.
    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Encapsulate to `ek` using `seed` as the message, returning `(ciphertext, shared secret)`.
    ///
    /// **`seed` is the message `m`, not a source of randomness to expand.** FIPS 203's
    /// `ML-KEM.Encaps_internal` takes it directly, and taking anything else here would make
    /// §5's derivation unable to pin the ciphertext.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] on a wrong seed length, [`Error::Kem`] on a malformed `ek` — which
    /// FIPS 203 requires be rejected rather than used.
    fn encapsulate(ek: &[u8], seed: &[u8]) -> Result<(Vec<u8>, Bytes32), Error>;

    /// Decapsulate `ct` under `dk_seed`'s key.
    ///
    /// # Why the seed and not the expanded key
    ///
    /// So that a caller holding only a delegated 64-byte tracking key can scan, which is the
    /// whole of §2.1's delegation story.
    ///
    /// # Errors
    ///
    /// [`Error::Kem`]. Note that ML-KEM's implicit rejection means a wrong ciphertext yields a
    /// *pseudorandom* secret rather than an error, so this fails only on a malformed input —
    /// and a scanner MUST treat both outcomes identically, per §2.5.
    fn decapsulate(dk_seed: &[u8], ct: &[u8]) -> Result<Bytes32, Error>;
}

/// ML-KEM-768, as specified in FIPS 203, unmodified.
///
/// # Why 768 at every schemeId 6 category
///
/// §1 injects ML-KEM-768 across the whole ladder rather than pairing each ML-DSA category with
/// a KEM of matching strength. That is a deliberate asymmetry: the announcement layer's
/// security is what the KEM protects and it does not vary by the spending rung's category.
/// `tools/derive_sizes.py` records it as the reason `ek` and `ct` do not vary by category.
///
/// # The anonymity property this rung needs
///
/// §9 requires **ANO-CCA**, and derives it rather than citing it: Bao–Pan (ePrint 2026/396)
/// give anonymity for stock FIPS 203 ML-KEM. The round-3 Kyber variant the Spirit reference
/// vendors has no such result, which is why §1 fixes stock.
pub struct MlKem768;

impl Kem for MlKem768 {
    const EK_BYTES: usize = 1_184;
    const CT_BYTES: usize = 1_088;
    const KEYGEN_SEED_BYTES: usize = 64;
    const ENCAP_SEED_BYTES: usize = 32;

    /// Returns `(ek, dk_seed)` — and the second element is the **64-byte seed handed back
    /// unchanged**, not an expanded key.
    ///
    /// That looks redundant and it is the point: the tracking key §2.1 delegates is the seed,
    /// so the type a caller stores after keygen must be the 64 bytes and never the 2 400. A
    /// signature returning an expanded `dk` would make the small tracking key an extra step a
    /// porter has to know to take, and `derive_sizes.py` asserts the two lengths apart.
    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let dz: [u8; 64] = seed.try_into().map_err(|_| Error::Malformed)?;
        let dk = <MlKem768Params as MlKemTrait>::DecapsulationKey::from_seed(
            Seed::try_from(dz.as_slice()).map_err(|_| Error::Malformed)?,
        );
        let ek = dk.encapsulation_key().to_bytes().to_vec();
        debug_assert_eq!(ek.len(), Self::EK_BYTES);
        Ok((ek, dz.to_vec()))
    }

    fn encapsulate(ek: &[u8], seed: &[u8]) -> Result<(Vec<u8>, Bytes32), Error> {
        let m: [u8; 32] = seed.try_into().map_err(|_| Error::Malformed)?;
        // FIPS 203 requires a malformed `ek` be REJECTED rather than used, which is what `new`
        // does and what a `from_bytes` that cannot fail would not.
        let key = ml_kem::Key::<<MlKem768Params as MlKemTrait>::EncapsulationKey>::try_from(ek)
            .map_err(|_| Error::Kem)?;
        let ek =
            <MlKem768Params as MlKemTrait>::EncapsulationKey::new(&key).map_err(|_| Error::Kem)?;
        // Deterministic in `m`. A fixture pinning `(ek, m)` therefore pins `ct` and `ss`, which
        // is what makes every §2 vector reproducible at all.
        let (ct, ss) = ek.encapsulate_deterministic(&m.into());
        debug_assert_eq!(ct.len(), Self::CT_BYTES);
        Ok((
            ct.to_vec(),
            ss.as_slice().try_into().map_err(|_| Error::Kem)?,
        ))
    }

    fn decapsulate(dk_seed: &[u8], ct: &[u8]) -> Result<Bytes32, Error> {
        let dz: [u8; 64] = dk_seed.try_into().map_err(|_| Error::Malformed)?;
        let ct = ml_kem::Ciphertext::<MlKem768Params>::try_from(ct).map_err(|_| Error::Kem)?;
        let dk = <MlKem768Params as MlKemTrait>::DecapsulationKey::from_seed(
            Seed::try_from(dz.as_slice()).map_err(|_| Error::Malformed)?,
        );
        // IMPLICIT REJECTION: a ciphertext addressed to somebody else returns a pseudorandom
        // secret and no error. There is no `Result` to unwrap here and that is the property the
        // whole ladder is shaped around -- §2.5 requires a scanner treat this outcome and a
        // real one identically, and §3.3 is why a candidate channel key is not evidence.
        let ss = dk.decapsulate(&ct);
        ss.as_slice().try_into().map_err(|_| Error::Kem)
    }
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

    /// NIST's ACVP `keyGen` case 26, from `vectors/tier1/ml-kem-768-acvp.json`.
    ///
    /// **Tier 1 is NIST's and nothing in it is ours to produce**, which is why this is the
    /// acceptance test for the library rather than a claim about our code. It checks the
    /// derandomised entry point specifically: `(d, z)` in, a fixed `ek` out.
    const ACVP_DZ: &str = "e582b7d75e6c80b05ae392a1fc9f7153b12390fd99930368cc67a768baebc8a0\
                           1cdacb8740c0b87c4a379575f187b367cbfa3b300bf591b109f79816e9cbe8f0";
    const ACVP_EK_HEAD: &str = "28c793778741b80b02b4339f2aa43472";
    const ACVP_EK_TAIL: &str = "c2644b605187b71a14bc4c8678fe8247";

    #[test]
    fn acvp_keygen_case_26() {
        let (ek, dk_seed) = MlKem768::keygen(&unhex(ACVP_DZ)).expect("64 bytes");
        assert_eq!(ek.len(), MlKem768::EK_BYTES, "ek is 1 184 B: 384*3 + 32");
        assert!(hexlify(&ek).starts_with(ACVP_EK_HEAD));
        assert!(hexlify(&ek).ends_with(ACVP_EK_TAIL));
        // The returned tracking key is the SEED, unchanged -- not the 2 400-byte expanded form.
        // §2.1 delegates these 64 bytes, and the difference is the whole delegation story.
        assert_eq!(dk_seed, unhex(ACVP_DZ));
        assert_eq!(dk_seed.len(), MlKem768::KEYGEN_SEED_BYTES);
    }

    /// NIST's ACVP `encapsulation` case 26. Deterministic in `m`, which is what lets a fixture
    /// pinning `(ek, m)` pin `ct` and `ss` — the property every §2 vector rests on.
    /// NIST's file itself, compiled in. No JSON dependency: the two fields this test needs are
    /// extracted by string search, which is enough for a fixed file and keeps a crate that
    /// implements a KEM from depending on a parser.
    const ACVP_JSON: &str = include_str!("../../../vectors/tier1/ml-kem-768-acvp.json");

    /// The first `"<key>": "<hex>"` appearing after `after` in the vendored file.
    fn acvp_field(after: &str, key: &str) -> Vec<u8> {
        let tail = ACVP_JSON.split_once(after).expect("section present").1;
        let pat = format!("\"{key}\": \"");
        let v = tail.split_once(&pat).expect("field present").1;
        unhex(v.split_once('"').expect("closing quote").0)
    }

    #[test]
    fn acvp_encapsulation_case_26() {
        let ek = acvp_field("\"encapsulation\"", "ek");
        let m = unhex("4e77596168711e913965d8175ac3bd76aab08b7f9385a02ae883cf6c6e17dd81");
        let (ct, ss) = MlKem768::encapsulate(&ek, &m).expect("a valid ek and a 32-byte m");
        assert_eq!(ct.len(), MlKem768::CT_BYTES, "ct is 1 088 B: 32*(10*3 + 4)");
        assert!(hexlify(&ct).starts_with("0385e8044d17e2b96b3f50ed28c25022"));
        assert!(hexlify(&ct).ends_with("cc8d90c80c1e19f1ab2c08646c0e3958"));
        assert_eq!(
            hexlify(&ss),
            "79d74f6c6c2d916bec47bd828fd9b67295a37f54927fab1263c0d122f1c6f1ed"
        );
        // Deterministic: the same `m` twice gives the same ciphertext.
        let (ct2, ss2) = MlKem768::encapsulate(&ek, &m).unwrap();
        assert_eq!((ct, ss), (ct2, ss2));
    }

    /// **NIST's own decapsulation cases, including the implicit-rejection ones.**
    ///
    /// Without these, decapsulation would be checked only against
    /// this same library's own encapsulation — `the_round_trip_agrees` below — which is
    /// circular: a KEM wrong in both directions consistently passes it. These cases carry
    /// NIST's expected secret, so they are an external witness.
    ///
    /// **Five of the ten are `modified ciphertext`, which IS implicit rejection**: the
    /// pseudorandom secret a foreign ciphertext yields is not arbitrary, it is a specified value
    /// — and that is what makes the property testable rather than merely asserted.
    ///
    /// `dk` is ACVP's expanded 2 400-byte form, not the `(d, z)` seed §1 requires, so this test
    /// reaches for `ml-kem`'s expanded entry point directly rather than going through
    /// [`Kem::decapsulate`]. That asymmetry is the point of §1's representation rule and is
    /// stated in the vendored file's own note.
    #[test]
    fn acvp_decapsulation_cases_including_implicit_rejection() {
        #[allow(deprecated)]
        let mut checked = 0;
        let mut rejections = 0;
        let mut rest = ACVP_JSON
            .split_once("\"decapsulation\"")
            .expect("the section")
            .1;
        while let Some((_, after)) = rest.split_once("\"reason\": \"") {
            let (reason, after) = after.split_once('"').expect("closing quote");
            let dk = unhex(&next_field(after, "dk"));
            let c = unhex(&next_field(after, "c"));
            let want = next_field(after, "k");
            assert_eq!(dk.len(), 2400, "ACVP's dk is the expanded form");

            let enc = ml_kem::ExpandedDecapsulationKey::<MlKem768Params>::try_from(dk.as_slice())
                .expect("2 400 bytes");
            // `from_expanded` is deprecated in favour of `from_seed`, and that deprecation
            // does NOT apply here: ACVP's `dk` IS the expanded form and there is no seed to
            // use instead. Our own code paths take the seed, which is what §1 requires.
            #[allow(deprecated)]
            let key = <MlKem768Params as MlKemTrait>::DecapsulationKey::from_expanded(&enc)
                .expect("a well-formed expanded key");
            let ct = ml_kem::Ciphertext::<MlKem768Params>::try_from(c.as_slice()).unwrap();
            let got = key.decapsulate(&ct);
            assert_eq!(hexlify(got.as_slice()), want, "reason: {reason}");

            checked += 1;
            if reason == "modified ciphertext" {
                rejections += 1;
            }
            rest = after;
        }
        assert_eq!(
            checked, 10,
            "all ten of NIST's ML-KEM-768 decapsulation cases"
        );
        assert_eq!(
            rejections, 5,
            "five are implicit rejection, and they are the point"
        );
    }

    /// The first `"<key>": "<hex>"` at or after `from`.
    fn next_field(from: &str, key: &str) -> String {
        let pat = format!("\"{key}\": \"");
        let v = from.split_once(&pat).expect("field present").1;
        v.split_once('"').expect("closing quote").0.to_owned()
    }

    /// The round trip through OUR entry points — the `(d, z)` seed rather than the expanded key.
    ///
    /// Circular on its own, which is why the ACVP cases above exist. What it adds is coverage of
    /// the seed path §1 actually requires, which no ACVP case uses.
    #[test]
    fn the_round_trip_agrees() {
        let (ek, dk_seed) = MlKem768::keygen(&unhex(ACVP_DZ)).unwrap();
        let m = [0x33u8; 32];
        let (ct, sender_ss) = MlKem768::encapsulate(&ek, &m).unwrap();
        let recipient_ss = MlKem768::decapsulate(&dk_seed, &ct).unwrap();
        assert_eq!(sender_ss, recipient_ss);
    }

    /// **Implicit rejection, and it is the property the whole ladder is shaped around.**
    ///
    /// A ciphertext addressed to somebody else does NOT fail. It returns a well-formed
    /// pseudorandom secret, which is why §2.5 forbids treating a decapsulation result as
    /// evidence and why §3.3 says a candidate channel key is not evidence of anything.
    #[test]
    fn decapsulating_a_foreign_ciphertext_does_not_fail() {
        let (_ek_ours, ours) = MlKem768::keygen(&unhex(ACVP_DZ)).unwrap();
        let (ek_theirs, theirs) = MlKem768::keygen(&[0x5A; 64]).unwrap();
        let m = [0x77u8; 32];
        let (ct, their_ss) = MlKem768::encapsulate(&ek_theirs, &m).unwrap();

        let our_ss = MlKem768::decapsulate(&ours, &ct)
            .expect("implicit rejection: this MUST NOT be an error");
        let recipient_ss = MlKem768::decapsulate(&theirs, &ct).unwrap();

        assert_eq!(
            recipient_ss, their_ss,
            "the intended recipient gets the real secret"
        );
        assert_ne!(our_ss, their_ss, "and we get a different, pseudorandom one");
        assert_ne!(our_ss, [0u8; 32], "which is not a zero or sentinel value");
    }

    /// Malformed inputs, which DO fail — and the distinction from implicit rejection is the
    /// one §2.5 turns on: a wrong length is a skip a scanner reaches by a different path than
    /// a foreign-but-well-formed ciphertext.
    #[test]
    fn wrong_lengths_are_errors() {
        assert!(MlKem768::keygen(&[0u8; 63]).is_err());
        assert!(MlKem768::keygen(&[0u8; 65]).is_err());
        let (ek, dk) = MlKem768::keygen(&unhex(ACVP_DZ)).unwrap();
        assert!(MlKem768::encapsulate(&ek, &[0u8; 31]).is_err());
        assert!(MlKem768::encapsulate(&ek[..1183], &[0u8; 32]).is_err());
        assert!(MlKem768::decapsulate(&dk, &[0u8; 1087]).is_err());
    }
}
