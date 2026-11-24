//! A second suite, defined outside the crate the way a later `schemeId` would be.
//!
//! The KEM is a [`Pair`] of two ML-KEM-768 instances, so the test needs no other KEM. It is a
//! stand-in for a pair from different families, not a proposal: what it checks is that the
//! construction takes another suite's lengths, seeds and domain separator without change, and
//! that schemeId 3 and the new suite cannot read each other's announcements.
use pqsa_core::{Error, ExportableSpendKey, SenderState, StealthScheme};
use pqsa_kem::{Kem, MlKem768, Pair};
use pqsa_per_payment::{Hybrid, MlKem768Suite, SchemeId3, Suite};

/// Two KEMs, a composite shared secret, and its own id and domain separator.
#[derive(Clone, Copy, Debug)]
struct TwoKemSuite;

impl Suite for TwoKemSuite {
    const SCHEME_ID: u64 = 0xffff_0001;
    const NAME: &'static str = "test suite: ML-KEM-768 pair";
    const DOMAIN_SEPARATOR: &'static [u8] = b"pq-stealth/test-suite/pair/v1";
    type Kem = Pair<MlKem768, MlKem768>;
}

/// schemeId 3's KEM under another id and domain separator.
#[derive(Clone, Copy, Debug)]
struct OtherSeparatorSuite;

impl Suite for OtherSeparatorSuite {
    const SCHEME_ID: u64 = 0xffff_0002;
    const NAME: &'static str = "test suite: schemeId 3's KEM, another separator";
    const DOMAIN_SEPARATOR: &'static [u8] = b"pq-stealth/test-suite/separator/v1";
    type Kem = MlKem768;
}

type TwoKem = Hybrid<TwoKemSuite>;
type OtherSeparator = Hybrid<OtherSeparatorSuite>;

fn seed(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(salt))
        .collect()
}

#[test]
fn a_second_suite_takes_its_lengths_from_its_kem() {
    assert_eq!(TwoKem::KEYGEN_SEED_BYTES, 64 + 128);
    assert_eq!(TwoKem::ANNOUNCE_SEED_BYTES, 32 + 64);
    assert_eq!(TwoKem::META_ADDRESS_BYTES, 66 + 2 * MlKem768::EK_BYTES);
    assert_eq!(TwoKem::EPHEMERAL_PUB_KEY_BYTES, 33 + 2 * MlKem768::CT_BYTES);
    assert_eq!(SchemeId3::META_ADDRESS_BYTES, 1250);
    assert_eq!(SchemeId3::EPHEMERAL_PUB_KEY_BYTES, 1121);
    assert_eq!(TwoKem::kem_id(), [MlKem768::id(), MlKem768::id()].concat());
    assert_eq!(SchemeId3::kem_id(), MlKem768::id());
}

#[test]
fn a_second_suite_round_trips_a_payment() {
    let (meta, master, tracking) = TwoKem::keygen(&seed(TwoKem::KEYGEN_SEED_BYTES, 3)).unwrap();
    let scanner = TwoKem::bind(&tracking, &meta).unwrap();
    let mut sender = SenderState::resume(&[0x5a; 32], 0);
    let seeded = TwoKem::announce(&meta, &sender.draw_seed::<TwoKem>().unwrap()).unwrap();
    for ann in [seeded, TwoKem::announce_random(&meta).unwrap()] {
        let (address, ephemeral, metadata) = TwoKem::announcement_to_bytes(&ann);
        assert_eq!(ephemeral.len(), TwoKem::EPHEMERAL_PUB_KEY_BYTES);
        let parsed = TwoKem::announcement_from_bytes(&address, &ephemeral, &metadata).unwrap();
        let matched = TwoKem::scan(&scanner, &parsed).expect("our own payment");
        let key = TwoKem::spend_key(&master, &matched).unwrap();
        let point = pqsa_ec::public_point(TwoKem::spend_key_bytes(&key).try_into().unwrap());
        assert_eq!(pqsa_ec::address_of(&point.unwrap()), address);
    }
    let wire = TwoKem::meta_to_bytes(&meta);
    assert_eq!(wire.len(), TwoKem::META_ADDRESS_BYTES);
    assert_eq!(
        TwoKem::meta_to_bytes(&TwoKem::meta_from_bytes(&wire).unwrap()),
        wire
    );
}

/// Each suite skips the other's shapes, so one registry and one announcer serve both.
#[test]
fn schemeid3_and_a_second_suite_skip_each_others_announcements() {
    let (meta2, _, _) = TwoKem::keygen(&seed(TwoKem::KEYGEN_SEED_BYTES, 3)).unwrap();
    let (meta3, _, _) = SchemeId3::keygen(&seed(SchemeId3::KEYGEN_SEED_BYTES, 3)).unwrap();
    let (a2, e2, m2) = TwoKem::announcement_to_bytes(&TwoKem::announce_random(&meta2).unwrap());
    let (a3, e3, m3) =
        SchemeId3::announcement_to_bytes(&SchemeId3::announce_random(&meta3).unwrap());
    assert!(SchemeId3::announcement_from_bytes(&a2, &e2, &m2).is_none());
    assert!(TwoKem::announcement_from_bytes(&a3, &e3, &m3).is_none());
    assert!(SchemeId3::meta_from_bytes(&TwoKem::meta_to_bytes(&meta2)).is_none());
    assert!(TwoKem::meta_from_bytes(&SchemeId3::meta_to_bytes(&meta3)).is_none());
}

/// Same keys, same randomness, same KEM: only the domain separator differs, and the payment
/// is a different one. Two suites sharing a KEM cannot produce each other's addresses.
#[test]
fn the_domain_separator_separates_suites_that_share_a_kem() {
    assert_ne!(
        MlKem768Suite::DOMAIN_SEPARATOR,
        OtherSeparatorSuite::DOMAIN_SEPARATOR
    );
    let keys = seed(SchemeId3::KEYGEN_SEED_BYTES, 9);
    let randomness = seed(SchemeId3::ANNOUNCE_SEED_BYTES, 11);
    let (meta3, _, tracking3) = SchemeId3::keygen(&keys).unwrap();
    let (meta_other, _, tracking_other) = OtherSeparator::keygen(&keys).unwrap();
    assert_eq!(
        SchemeId3::meta_to_bytes(&meta3),
        OtherSeparator::meta_to_bytes(&meta_other)
    );

    let ann3 = SchemeId3::announce(&meta3, &randomness).unwrap();
    let ann_other = OtherSeparator::announce(&meta_other, &randomness).unwrap();
    assert_eq!(ann3.epk, ann_other.epk);
    assert_eq!(ann3.ct(), ann_other.ct());
    assert_ne!(ann3.stealth_address, ann_other.stealth_address);

    let (address, ephemeral, metadata) = OtherSeparator::announcement_to_bytes(&ann_other);
    let as3 = SchemeId3::announcement_from_bytes(&address, &ephemeral, &metadata).unwrap();
    let scanner3 = SchemeId3::bind(&tracking3, &meta3).unwrap();
    assert!(
        SchemeId3::scan(&scanner3, &as3).is_none(),
        "schemeId 3's scanner derives another ss from the same bytes and finds nothing"
    );
    let scanner_other = OtherSeparator::bind(&tracking_other, &meta_other).unwrap();
    assert!(OtherSeparator::scan(&scanner_other, &ann_other).is_some());
}

/// §2.1's guard reaches every component of a composite KEM's seed.
#[test]
fn the_delegation_guard_covers_a_composite_seed() {
    let mut keys = seed(TwoKem::KEYGEN_SEED_BYTES, 3);
    let spending = keys[..32].to_vec();
    keys[128..160].copy_from_slice(&spending); // `d` of the second KEM
    assert_eq!(
        TwoKem::keygen(&keys).unwrap_err(),
        Error::SpendingKeyDelegated
    );
}
