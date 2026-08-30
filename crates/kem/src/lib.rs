//! ML-KEM-768 via RustCrypto `ml-kem`, derandomised. §1.
//!
//! Keygen is FIPS 203 `KeyGen_internal(d, z)`. Encapsulation is `Encaps_internal(ek, m)`:
//! the 32-byte seed is the message `m`, so a fixture that pins `(ek, m)` pins `(ct, ss)`.
//! This is not the public `Encaps` API (no RBG). Decapsulation is ordinary `Decapsulate`.

use ml_kem::kem::Kem as MlKemTrait;
use ml_kem::{Decapsulate, KeyExport, MlKem768 as MlKem768Params, Seed};
use pqsa_core::{Bytes32, Error};

/// Derandomised KEM. Sizes from FIPS 203 (`tools/derive_sizes.py`).
pub trait Kem {
    /// Encapsulation-key length (1 184 for ML-KEM-768).
    const EK_BYTES: usize;
    /// Ciphertext length (1 088 for ML-KEM-768).
    const CT_BYTES: usize;
    /// Keygen seed length: 64-byte `(d, z)`, not the 2 400-byte expanded `dk`. §2.1.
    const KEYGEN_SEED_BYTES: usize;
    /// Encapsulation seed length: 32-byte message `m`.
    const ENCAP_SEED_BYTES: usize;

    /// `(ek, dk_seed)` from a seed of length [`Self::KEYGEN_SEED_BYTES`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `seed` has the wrong length.
    fn keygen(seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// `(ct, ss)` from `ek` and message `m` = `seed`. Deterministic.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `seed` has the wrong length; [`Error::Kem`] if `ek` fails
    /// ML-KEM's encapsulation-key checks.
    fn encapsulate(ek: &[u8], seed: &[u8]) -> Result<(Vec<u8>, Bytes32), Error>;

    /// Decapsulate `ct` under the 64-byte `(d, z)` seed.
    ///
    /// Implicit rejection: a well-formed ciphertext for someone else returns a pseudorandom
    /// secret, not an error. §2.5.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `dk_seed` has the wrong length; [`Error::Kem`] if `ct` has the
    /// wrong length.
    fn decapsulate(dk_seed: &[u8], ct: &[u8]) -> Result<Bytes32, Error>;
}

/// ML-KEM-768 as in FIPS 203.
pub struct MlKem768;

impl Kem for MlKem768 {
    const EK_BYTES: usize = 1_184;
    const CT_BYTES: usize = 1_088;
    const KEYGEN_SEED_BYTES: usize = 64;
    const ENCAP_SEED_BYTES: usize = 32;

    /// Returns `(ek, dk_seed)` with `dk_seed` the 64-byte input, not the expanded key.
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
        // `new` rejects a malformed ek.
        let key = ml_kem::Key::<<MlKem768Params as MlKemTrait>::EncapsulationKey>::try_from(ek)
            .map_err(|_| Error::Kem)?;
        let ek =
            <MlKem768Params as MlKemTrait>::EncapsulationKey::new(&key).map_err(|_| Error::Kem)?;
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
        // Implicit rejection: a foreign well-formed ciphertext returns a pseudorandom secret.
        let ss = dk.decapsulate(&ct);
        ss.as_slice().try_into().map_err(|_| Error::Kem)
    }
}

#[cfg(test)]
mod acvp;
