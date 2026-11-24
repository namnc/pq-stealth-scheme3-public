//! The KEM a hybrid suite plugs in, and ML-KEM-768 via RustCrypto `ml-kem`, derandomised. §1.
//!
//! Keygen is FIPS 203 `KeyGen_internal(d, z)`. [`Kem::encapsulate`] is `Encaps_internal(ek, m)`:
//! the 32-byte seed is the message `m`, so a fixture that pins `(ek, m)` pins `(ct, ss)`.
//! [`Kem::encapsulate_random`] is the public `ML-KEM.Encaps(ek)` (FIPS 203 Algorithm 20): `m`
//! from the operating system's CSPRNG, then `Encaps_internal`. Decapsulation is ordinary
//! `Decapsulate`.
//!
//! [`Pair`] puts two KEMs side by side, which is how a suite combines KEMs from different
//! families: keys, ciphertexts, seeds and shared secrets are each the first KEM's followed by
//! the second's.

use ml_kem::kem::Kem as MlKemTrait;
use ml_kem::{Decapsulate, KeyExport, MlKem768 as MlKem768Params, Seed};
use pqsa_core::{Error, bare_kem_id};
use zeroize::Zeroizing;

/// KEM with seeded and random encapsulation. Sizes from each KEM's specification
/// (`tools/derive_sizes.py` for ML-KEM-768).
pub trait Kem {
    /// Encapsulation-key length (1 184 for ML-KEM-768).
    const EK_BYTES: usize;
    /// Ciphertext length (1 088 for ML-KEM-768).
    const CT_BYTES: usize;
    /// Shared-secret length (32 for ML-KEM-768).
    const SS_BYTES: usize;
    /// Keygen seed length: 64-byte `(d, z)` for ML-KEM-768, not the 2 400-byte expanded `dk`.
    /// §2.1. [`Self::keygen`] returns this seed as `dk_seed`, so it is also what a tracking key
    /// stores.
    const KEYGEN_SEED_BYTES: usize;
    /// Encapsulation seed length: 32-byte message `m` for ML-KEM-768.
    const ENCAP_SEED_BYTES: usize;

    /// Decapsulation key expanded from `dk_seed`, for a scanner to hold rather than rebuild
    /// for every ciphertext.
    type DecapsulationKey: Clone;

    /// `u64be(|name|) || name` for a bare KEM, or the components' ids in order for a
    /// composite. Not from the ERC: it separates the seed streams of `pqsa_core::SenderState`.
    fn id() -> Vec<u8>;

    /// `(ek, dk_seed)` from a seed of length [`Self::KEYGEN_SEED_BYTES`]. `dk_seed` is the seed.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `seed` has the wrong length.
    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error>;

    /// `(ct, ss)` from `ek` and an encapsulation seed (ML-KEM's `m`). Deterministic.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `seed` has the wrong length; [`Error::Kem`] if `ek` fails the
    /// KEM's encapsulation-key checks.
    fn encapsulate(ek: &[u8], seed: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error>;

    /// [`Self::encapsulate`] with the seed from the operating system's CSPRNG: for ML-KEM,
    /// `ML-KEM.Encaps(ek)`. The sender's encapsulation. §2.4.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] if the operating system's RNG fails; [`Error::Kem`] if `ek` fails the
    /// KEM's encapsulation-key checks.
    fn encapsulate_random(ek: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let mut m = Zeroizing::new(vec![0u8; Self::ENCAP_SEED_BYTES]);
        pqsa_core::os_random(&mut m)?;
        Self::encapsulate(ek, &m)
    }

    /// Expand `dk_seed` into the decapsulation key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `dk_seed` has the wrong length.
    fn decapsulation_key(dk_seed: &[u8]) -> Result<Self::DecapsulationKey, Error>;

    /// Decapsulate `ct` with an expanded key.
    ///
    /// Implicit rejection: a well-formed ciphertext for someone else returns a pseudorandom
    /// secret, not an error. §2.5.
    ///
    /// # Errors
    ///
    /// [`Error::Kem`] if `ct` has the wrong length.
    fn decapsulate_with(
        dk: &Self::DecapsulationKey,
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error>;

    /// Decapsulate `ct` under `dk_seed`: [`Self::decapsulation_key`], then
    /// [`Self::decapsulate_with`]. A scanner should expand once and keep the key instead.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `dk_seed` has the wrong length; [`Error::Kem`] if `ct` has the
    /// wrong length.
    fn decapsulate(dk_seed: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        Self::decapsulate_with(&Self::decapsulation_key(dk_seed)?, ct)
    }
}

/// ML-KEM-768 as in FIPS 203.
pub struct MlKem768;

impl Kem for MlKem768 {
    const EK_BYTES: usize = 1_184;
    const CT_BYTES: usize = 1_088;
    const SS_BYTES: usize = 32;
    const KEYGEN_SEED_BYTES: usize = 64;
    const ENCAP_SEED_BYTES: usize = 32;

    type DecapsulationKey = <MlKem768Params as MlKemTrait>::DecapsulationKey;

    /// `u64be(10) || "ML-KEM-768"`, 18 bytes.
    fn id() -> Vec<u8> {
        bare_kem_id(b"ML-KEM-768")
    }

    /// Returns `(ek, dk_seed)` with `dk_seed` the 64-byte input, not the expanded key.
    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let dz = Zeroizing::new(Seed::try_from(seed).map_err(|_| Error::Malformed)?);
        let dk = <MlKem768Params as MlKemTrait>::DecapsulationKey::from_seed(*dz);
        let ek = dk.encapsulation_key().to_bytes().to_vec();
        debug_assert_eq!(ek.len(), Self::EK_BYTES);
        Ok((ek, Zeroizing::new(dz.to_vec())))
    }

    fn encapsulate(ek: &[u8], seed: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let m = Zeroizing::new(ml_kem::B32::try_from(seed).map_err(|_| Error::Malformed)?);
        let key = ml_kem::Key::<<MlKem768Params as MlKemTrait>::EncapsulationKey>::try_from(ek)
            .map_err(|_| Error::Kem)?;
        let ek =
            <MlKem768Params as MlKemTrait>::EncapsulationKey::new(&key).map_err(|_| Error::Kem)?;
        let (ct, ss) = ek.encapsulate_deterministic(&m);
        let ss = Zeroizing::new(ss);
        debug_assert_eq!(ct.len(), Self::CT_BYTES);
        Ok((ct.to_vec(), Zeroizing::new(ss.to_vec())))
    }

    fn decapsulation_key(dk_seed: &[u8]) -> Result<Self::DecapsulationKey, Error> {
        let dz = Zeroizing::new(Seed::try_from(dk_seed).map_err(|_| Error::Malformed)?);
        Ok(<MlKem768Params as MlKemTrait>::DecapsulationKey::from_seed(
            *dz,
        ))
    }

    fn decapsulate_with(
        dk: &Self::DecapsulationKey,
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let ct = ml_kem::Ciphertext::<MlKem768Params>::try_from(ct).map_err(|_| Error::Kem)?;
        // Implicit rejection: a foreign well-formed ciphertext returns a pseudorandom secret.
        let ss = Zeroizing::new(dk.decapsulate(&ct));
        Ok(Zeroizing::new(ss.to_vec()))
    }
}

/// Two KEMs side by side: every key, ciphertext, seed and shared secret is `A`'s followed by
/// `B`'s. A suite that hedges across KEM families uses one, and the hybrid combiner binds both
/// ciphertexts and both keys, so the combined secret stays secret while either KEM holds.
pub struct Pair<A, B>(core::marker::PhantomData<(A, B)>);

/// Split `bytes` at `at`, or [`Error::Malformed`] if it is not `at + rest` bytes long.
fn split(bytes: &[u8], at: usize, rest: usize, error: Error) -> Result<(&[u8], &[u8]), Error> {
    if bytes.len() != at + rest {
        return Err(error);
    }
    Ok(bytes.split_at(at))
}

fn concat(a: &[u8], b: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(a.len() + b.len()));
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

impl<A: Kem, B: Kem> Kem for Pair<A, B> {
    const EK_BYTES: usize = A::EK_BYTES + B::EK_BYTES;
    const CT_BYTES: usize = A::CT_BYTES + B::CT_BYTES;
    const SS_BYTES: usize = A::SS_BYTES + B::SS_BYTES;
    const KEYGEN_SEED_BYTES: usize = A::KEYGEN_SEED_BYTES + B::KEYGEN_SEED_BYTES;
    const ENCAP_SEED_BYTES: usize = A::ENCAP_SEED_BYTES + B::ENCAP_SEED_BYTES;

    type DecapsulationKey = (A::DecapsulationKey, B::DecapsulationKey);

    fn id() -> Vec<u8> {
        [A::id(), B::id()].concat()
    }

    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let (a, b) = split(
            seed,
            A::KEYGEN_SEED_BYTES,
            B::KEYGEN_SEED_BYTES,
            Error::Malformed,
        )?;
        let (ek_a, dk_a) = A::keygen(a)?;
        let (ek_b, dk_b) = B::keygen(b)?;
        Ok(([ek_a, ek_b].concat(), concat(&dk_a, &dk_b)))
    }

    fn encapsulate(ek: &[u8], seed: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        let (ek_a, ek_b) = split(ek, A::EK_BYTES, B::EK_BYTES, Error::Kem)?;
        let (m_a, m_b) = split(
            seed,
            A::ENCAP_SEED_BYTES,
            B::ENCAP_SEED_BYTES,
            Error::Malformed,
        )?;
        let (ct_a, ss_a) = A::encapsulate(ek_a, m_a)?;
        let (ct_b, ss_b) = B::encapsulate(ek_b, m_b)?;
        Ok(([ct_a, ct_b].concat(), concat(&ss_a, &ss_b)))
    }

    fn decapsulation_key(dk_seed: &[u8]) -> Result<Self::DecapsulationKey, Error> {
        let (a, b) = split(
            dk_seed,
            A::KEYGEN_SEED_BYTES,
            B::KEYGEN_SEED_BYTES,
            Error::Malformed,
        )?;
        Ok((A::decapsulation_key(a)?, B::decapsulation_key(b)?))
    }

    fn decapsulate_with(
        dk: &Self::DecapsulationKey,
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (ct_a, ct_b) = split(ct, A::CT_BYTES, B::CT_BYTES, Error::Kem)?;
        let ss_a = A::decapsulate_with(&dk.0, ct_a)?;
        let ss_b = B::decapsulate_with(&dk.1, ct_b)?;
        Ok(concat(&ss_a, &ss_b))
    }
}

#[cfg(test)]
mod acvp;

#[cfg(test)]
mod pair {
    use super::*;

    type Two = Pair<MlKem768, MlKem768>;

    fn seed(len: usize, salt: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(29) ^ salt)
            .collect()
    }

    /// Each half is exactly what the component KEM gives on its half of the input.
    #[test]
    fn a_pair_is_its_components_side_by_side() {
        let (k, m) = (
            seed(Two::KEYGEN_SEED_BYTES, 1),
            seed(Two::ENCAP_SEED_BYTES, 2),
        );
        let (ek, dk_seed) = Two::keygen(&k).unwrap();
        let (ek_a, _) = MlKem768::keygen(&k[..64]).unwrap();
        let (ek_b, _) = MlKem768::keygen(&k[64..]).unwrap();
        assert_eq!(ek, [ek_a.clone(), ek_b.clone()].concat());
        assert_eq!(
            dk_seed.as_slice(),
            k.as_slice(),
            "dk_seed is the keygen seed"
        );

        let (ct, ss) = Two::encapsulate(&ek, &m).unwrap();
        let (ct_a, ss_a) = MlKem768::encapsulate(&ek_a, &m[..32]).unwrap();
        let (ct_b, ss_b) = MlKem768::encapsulate(&ek_b, &m[32..]).unwrap();
        assert_eq!(ct, [ct_a, ct_b].concat());
        assert_eq!(ss.as_slice(), [ss_a.as_slice(), ss_b.as_slice()].concat());
        assert_eq!(ss.len(), Two::SS_BYTES);

        assert_eq!(Two::decapsulate(&dk_seed, &ct).unwrap(), ss);
        let dk = Two::decapsulation_key(&dk_seed).unwrap();
        assert_eq!(Two::decapsulate_with(&dk, &ct).unwrap(), ss);
        assert_eq!(Two::id(), [MlKem768::id(), MlKem768::id()].concat());
    }

    /// A ciphertext for someone else is implicit rejection in both halves, not an error.
    #[test]
    fn a_foreign_ciphertext_is_rejected_implicitly_in_both_halves() {
        let (_, ours) = Two::keygen(&seed(128, 3)).unwrap();
        let (their_ek, their_dk) = Two::keygen(&seed(128, 4)).unwrap();
        let (ct, their_ss) = Two::encapsulate(&their_ek, &seed(64, 5)).unwrap();
        assert_eq!(Two::decapsulate(&their_dk, &ct).unwrap(), their_ss);
        let our_ss = Two::decapsulate(&ours, &ct).expect("implicit rejection");
        assert_ne!(our_ss[..32], their_ss[..32]);
        assert_ne!(our_ss[32..], their_ss[32..]);
    }

    /// Every length is checked against the sum, so a half-length input cannot be split wrong.
    #[test]
    fn a_pair_checks_every_length() {
        let (ek, dk_seed) = Two::keygen(&seed(128, 6)).unwrap();
        let (ct, _) = Two::encapsulate(&ek, &seed(64, 7)).unwrap();
        assert_eq!(Two::keygen(&seed(127, 6)).unwrap_err(), Error::Malformed);
        assert_eq!(
            Two::encapsulate(&ek[1..], &seed(64, 7)).unwrap_err(),
            Error::Kem
        );
        assert_eq!(
            Two::encapsulate(&ek, &seed(63, 7)).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            Two::decapsulate(&dk_seed[1..], &ct).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            Two::decapsulate(&dk_seed, &ct[1..]).unwrap_err(),
            Error::Kem
        );
    }
}
