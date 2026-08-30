//! NIST ACVP cases from `vectors/tier1/ml-kem-768-acvp.json`.
//!
//! Keygen and encapsulation run through [`MlKem768`] and compare every byte
//! NIST published. Decapsulation cases use a 2 400-byte expanded `dk`, which
//! [`MlKem768::decapsulate`] does not accept; those cases go through `ml-kem`
//! `from_expanded`.

use super::*;
use ml_kem::kem::Kem as MlKemTrait;
use ml_kem::{Decapsulate, MlKem768 as MlKem768Params};
use serde_json::Value;
use std::sync::OnceLock;

const ACVP_JSON: &str = include_str!("../../../vectors/tier1/ml-kem-768-acvp.json");

fn acvp() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| {
        serde_json::from_slice(ACVP_JSON.as_bytes()).expect("vendored ACVP file is JSON")
    })
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("ACVP field {key}"));
    hex::decode(s).unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn cases(key: &str) -> &'static [Value] {
    acvp()
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("ACVP section {key}"))
}

fn tc_id(v: &Value) -> u64 {
    v.get("tcId")
        .and_then(Value::as_u64)
        .expect("every ACVP case has tcId")
}

fn keygen_dz(case: &Value) -> Vec<u8> {
    let mut dz = hx(case, "d");
    dz.extend_from_slice(&hx(case, "z"));
    dz
}

/// `KeyGen_internal(d, z)` for every vendored keyGen case; `ek` compared in full.
#[test]
fn acvp_keygen_matches_nist() {
    let rows = cases("keygen");
    assert!(!rows.is_empty(), "the vendored file carries keyGen cases");
    for case in rows {
        let dz = keygen_dz(case);
        let (ek, dk_seed) =
            MlKem768::keygen(&dz).unwrap_or_else(|_| panic!("tcId {}", tc_id(case)));
        assert_eq!(
            dk_seed,
            dz,
            "tcId {}: dk is the 64-byte seed, not expanded",
            tc_id(case)
        );
        assert_eq!(ek, hx(case, "ek"), "tcId {}: full ek", tc_id(case));
    }
}

/// `Encaps_internal(ek, m)` for every vendored encapsulation case; `ct` and `ss` in full.
#[test]
fn acvp_encaps_matches_nist() {
    let rows = cases("encapsulation");
    assert!(!rows.is_empty());
    for case in rows {
        let ek = hx(case, "ek");
        let m = hx(case, "m");
        let (ct, ss) =
            MlKem768::encapsulate(&ek, &m).unwrap_or_else(|_| panic!("tcId {}", tc_id(case)));
        assert_eq!(ct, hx(case, "c"), "tcId {}: full ct", tc_id(case));
        assert_eq!(ss.as_slice(), hx(case, "k"), "tcId {}: ss", tc_id(case));
        let again = MlKem768::encapsulate(&ek, &m).expect("deterministic");
        assert_eq!((ct, ss), again);
    }
}

/// NIST decapsulation, including five `modified ciphertext` implicit rejections.
///
/// **Not** [`MlKem768::decapsulate`]: ACVP's `dk` is the 2 400-byte expanded form
/// and those cases do not include `(d, z)`.
#[test]
fn nist_expanded_dk_decaps_matches_acvp() {
    let rows = cases("decapsulation");
    let mut rejections = 0;
    for case in rows {
        let dk = hx(case, "dk");
        let c = hx(case, "c");
        let want = hx(case, "k");
        let reason = case
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        assert_eq!(dk.len(), 2400, "tcId {}: expanded dk", tc_id(case));

        let enc = ml_kem::ExpandedDecapsulationKey::<MlKem768Params>::try_from(dk.as_slice())
            .unwrap_or_else(|_| panic!("tcId {} expanded key", tc_id(case)));
        #[allow(deprecated)]
        let key = <MlKem768Params as MlKemTrait>::DecapsulationKey::from_expanded(&enc)
            .unwrap_or_else(|_| panic!("tcId {} from_expanded", tc_id(case)));
        let ct = ml_kem::Ciphertext::<MlKem768Params>::try_from(c.as_slice())
            .unwrap_or_else(|_| panic!("tcId {} ct", tc_id(case)));
        let got = key.decapsulate(&ct);
        assert_eq!(got.as_slice(), want, "tcId {} ({reason})", tc_id(case));
        if reason == "modified ciphertext" {
            rejections += 1;
        }
    }
    assert_eq!(rows.len(), 10, "all ten ML-KEM-768 decapsulation cases");
    assert_eq!(rejections, 5, "five are implicit rejection");
}

/// Production seed wrapper: encapsulate then [`MlKem768::decapsulate`].
#[test]
fn production_decapsulate_round_trips_acvp_key() {
    let dz = keygen_dz(&cases("keygen")[0]);
    let (ek, dk_seed) = MlKem768::keygen(&dz).expect("ACVP (d, z)");
    let m = [0x33u8; 32];
    let (ct, sender_ss) = MlKem768::encapsulate(&ek, &m).expect("valid ek");
    let recipient_ss = MlKem768::decapsulate(&dk_seed, &ct).expect("seed API");
    assert_eq!(sender_ss, recipient_ss);
}

/// A well-formed ciphertext for someone else returns a secret, not an error.
#[test]
fn decapsulating_a_foreign_ciphertext_does_not_fail() {
    let dz = keygen_dz(&cases("keygen")[0]);
    let (_ek_ours, ours) = MlKem768::keygen(&dz).unwrap();
    let (ek_theirs, theirs) = MlKem768::keygen(&[0x5A; 64]).unwrap();
    let m = [0x77u8; 32];
    let (ct, their_ss) = MlKem768::encapsulate(&ek_theirs, &m).unwrap();

    let our_ss =
        MlKem768::decapsulate(&ours, &ct).expect("implicit rejection: this MUST NOT be an error");
    let recipient_ss = MlKem768::decapsulate(&theirs, &ct).unwrap();
    assert_eq!(recipient_ss, their_ss);
    assert_ne!(our_ss, their_ss);
    assert_ne!(our_ss, [0u8; 32]);
}

/// Wrong lengths are errors. A 2 400-byte expanded `dk` must not be taken as a seed.
#[test]
fn wrong_lengths_are_errors() {
    let dz = keygen_dz(&cases("keygen")[0]);
    for len in [0, 63, 65, 96, 2400] {
        assert!(
            matches!(MlKem768::keygen(&vec![0; len]), Err(Error::Malformed)),
            "keygen seed length {len}"
        );
    }
    let (ek, dk) = MlKem768::keygen(&dz).unwrap();
    for len in [0, 31, 33] {
        assert!(
            MlKem768::encapsulate(&ek, &vec![0; len]).is_err(),
            "encapsulation message length {len}"
        );
    }
    for len in [0, 1183, 1185] {
        assert!(
            MlKem768::encapsulate(&vec![0; len], &[0; 32]).is_err(),
            "encapsulation key length {len}"
        );
    }
    for len in [0, 1087, 1089] {
        assert!(
            MlKem768::decapsulate(&dk, &vec![0; len]).is_err(),
            "ciphertext length {len}"
        );
    }

    let expanded = hx(&cases("decapsulation")[0], "dk");
    let ct = hx(&cases("decapsulation")[0], "c");
    assert_eq!(expanded.len(), 2400);
    assert!(
        matches!(MlKem768::decapsulate(&expanded, &ct), Err(Error::Malformed)),
        "the seed API must reject the expanded form rather than taking a 64-byte prefix"
    );
}
