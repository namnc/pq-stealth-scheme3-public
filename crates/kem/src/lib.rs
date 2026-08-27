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

    /// NIST ACVP keyGen case 26.
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
        assert_eq!(dk_seed, unhex(ACVP_DZ));
        assert_eq!(dk_seed.len(), MlKem768::KEYGEN_SEED_BYTES);
    }

    /// Vendored ACVP JSON (string-sliced; no serde).
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
        let (ct2, ss2) = MlKem768::encapsulate(&ek, &m).unwrap();
        assert_eq!((ct, ss), (ct2, ss2));
    }

    /// All 10 ACVP decapsulation cases (5 implicit-rejection). Uses expanded `dk`; our API takes the seed.
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
            // ACVP ships expanded dk; our production path is from_seed.
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

    /// Round-trip through the seed API (ACVP cases use expanded dk).
    #[test]
    fn the_round_trip_agrees() {
        let (ek, dk_seed) = MlKem768::keygen(&unhex(ACVP_DZ)).unwrap();
        let m = [0x33u8; 32];
        let (ct, sender_ss) = MlKem768::encapsulate(&ek, &m).unwrap();
        let recipient_ss = MlKem768::decapsulate(&dk_seed, &ct).unwrap();
        assert_eq!(sender_ss, recipient_ss);
    }

    /// Foreign well-formed ct does not error.
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

    /// Wrong lengths are errors; implicit rejection is not.
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
