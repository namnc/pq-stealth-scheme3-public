//! Spec vectors from `vectors/section-*.json`.
//!
//! Expected bytes come from the committed fixtures, not from this implementation.
//! `reduce_to_scalar` is crate-private; this module stays under `src/` so it can call it.

use super::*;
use pqsa_core::{Bytes32, Error, StealthScheme, VIEW_TAG_BYTES};
use pqsa_kem::{Kem, MlKem768};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

const SECTION_1: &str = include_str!("../../../vectors/section-1.json");
const SECTION_2_9: &str = include_str!("../../../vectors/section-2_9.json");
const ACVP: &str = include_str!("../../../vectors/tier1/ml-kem-768-acvp.json");

const SECTION_1_CASES: &[&str] = &[
    "V1-01", "V1-02", "V1-03", "V1-04", "V1-05", "V1-06", "V1-07",
];
const SECTION_2_9_CASES: &[&str] = &[
    "V3-01", "V3-02", "V3-02a", "V3-03", "V3-04", "V3-05", "V3-06", "V3-06a", "V3-06b", "V3-07",
    "V3-08", "V3-08a", "V3-09", "V3-10", "V3-11", "V3-12", "V3-13", "V3-14", "V3-15",
];

fn parse(raw: &str) -> Value {
    serde_json::from_slice(raw.as_bytes()).expect("committed fixture is JSON")
}

fn section_1() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(SECTION_1))
}

fn section_2_9() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(SECTION_2_9))
}

fn acvp() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(ACVP))
}

fn acvp_keygen_for_dz(dz: &[u8]) -> &'static Value {
    obj(acvp(), "keygen")
        .as_array()
        .expect("ACVP keygen is an array")
        .iter()
        .find(|case| {
            let mut got = hx(case, "d");
            got.extend_from_slice(&hx(case, "z"));
            got == dz
        })
        .unwrap_or_else(|| panic!("no ACVP keygen case has this (d, z)"))
}

fn row<'a>(doc: &'a Value, id: &str) -> &'a Value {
    doc.get("vectors")
        .and_then(|v| v.get(id))
        .unwrap_or_else(|| panic!("fixture missing {id}"))
}

fn obj<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    obj(v, key)
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

fn u64_field(v: &Value, key: &str) -> u64 {
    obj(v, key)
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is not a u64"))
}

fn u64_array(v: &Value, key: &str) -> Vec<u64> {
    obj(v, key)
        .as_array()
        .unwrap_or_else(|| panic!("{key} is not an array"))
        .iter()
        .map(|value| {
            value
                .as_u64()
                .unwrap_or_else(|| panic!("{key} contains a non-u64 value"))
        })
        .collect()
}

fn hx(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn b32(v: &Value, key: &str) -> Bytes32 {
    hx(v, key)
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{key} is {} bytes, not 32", b.len()))
}

fn point(bytes: &[u8]) -> pqsa_ec::CompressedPoint {
    pqsa_ec::decode_point(bytes).expect("fixture point is SEC1 compressed")
}

fn encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn sha256(parts: &[&[u8]]) -> Bytes32 {
    Sha256::digest(parts.concat()).into()
}

fn v3_09_seed() -> Vec<u8> {
    hx(obj(row(section_2_9(), "V3-09"), "given"), "keygen_seed")
}

fn v3_09_meta_bytes() -> Vec<u8> {
    hx(obj(row(section_2_9(), "V3-09"), "expect"), "meta_address")
}

fn combine_parts(ds: &[u8], parts: &Value) -> Bytes32 {
    combine_secrets(
        ds,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(parts, "ct"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .expect("V3-06 parts have schemeId 3 lengths")
}

fn vector_ids(doc: &Value) -> BTreeSet<&str> {
    obj(doc, "vectors")
        .as_object()
        .expect("vectors is an object")
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn every_committed_vector_has_a_rust_case() {
    assert_eq!(
        vector_ids(section_1()),
        SECTION_1_CASES.iter().copied().collect()
    );
    assert_eq!(
        vector_ids(section_2_9()),
        SECTION_2_9_CASES.iter().copied().collect()
    );
}

// --- §1 ------------------------------------------------------------------

#[test]
fn v1_01_offset_of_ss() {
    let v = row(section_1(), "V1-01");
    let ss = b32(obj(v, "given"), "ss");
    let expect = obj(v, "expect");
    let base = sha256(&[DS_OFFSET, &ss]);
    assert_eq!(encode(&base), s(expect, "base"));
    let (offset, _) = derive_from_shared_secret(&ss).expect("this ss reduces at counter 0");
    assert_eq!(encode(&offset), s(expect, "offset"));
    assert_eq!(u64_field(expect, "counter"), 0, "offset == unhashed base");
    assert_eq!(offset, base);
}

#[test]
fn v1_02_digest_is_big_endian() {
    let v = row(section_1(), "V1-02");
    let given = obj(v, "given");
    let base = b32(given, "base");
    let offset = reduce_to_scalar(&base).expect("this base is already a valid scalar");
    assert_eq!(encode(&offset), s(obj(v, "expect"), "offset_big_endian"));
    assert_ne!(
        encode(&offset),
        s(obj(v, "wrong"), "offset_little_endian"),
        "little-endian read of the same digest is a different scalar"
    );
}

#[test]
fn v1_03_base_zero_retries() {
    let v = row(section_1(), "V1-03");
    let base = b32(obj(v, "given"), "base");
    let expect = obj(v, "expect");
    assert!(
        pqsa_ec::public_point(&base).is_err(),
        "counter 0 must not accept 0"
    );
    let offset = reduce_to_scalar(&base).expect("counter 1 yields a valid scalar");
    assert_eq!(u64_field(expect, "counter"), 1);
    assert_eq!(encode(&offset), s(expect, "offset"));
    assert_eq!(offset, sha256(&[DS_OFFSET, &base, &[1]]));
    assert_ne!(encode(&offset), s(obj(v, "wrong"), "offset"));
}

#[test]
fn v1_04_base_n_retries() {
    let v = row(section_1(), "V1-04");
    let base = b32(obj(v, "given"), "base");
    let expect = obj(v, "expect");
    assert!(
        pqsa_ec::public_point(&base).is_err(),
        "n is not a valid scalar; a silent reduce-mod-n would yield 0"
    );
    let offset = reduce_to_scalar(&base).expect("counter 1 yields a valid scalar");
    assert_eq!(u64_field(expect, "counter"), 1);
    assert_eq!(encode(&offset), s(expect, "offset"));
    assert_eq!(offset, sha256(&[DS_OFFSET, &base, &[1]]));
}

#[test]
fn v1_05_n_minus_1_accepted() {
    let v = row(section_1(), "V1-05");
    let base = b32(obj(v, "given"), "base");
    let expect = obj(v, "expect");
    let offset = reduce_to_scalar(&base).expect("n-1 is a valid scalar");
    assert_eq!(u64_field(expect, "counter"), 0);
    assert_eq!(encode(&offset), s(expect, "offset"));
    assert_eq!(offset, base);
}

#[test]
fn v1_06_counter_is_one_byte() {
    let v = row(section_1(), "V1-06");
    let given = obj(v, "given");
    let base = b32(given, "base");
    assert_eq!(u64_field(given, "counter"), 1);
    let digest = sha256(&[DS_OFFSET, &base, &[1]]);
    assert_eq!(encode(&digest), s(obj(v, "expect"), "digest"));
    let wrong = obj(v, "wrong");
    assert_ne!(encode(&digest), s(wrong, "u32be"));
    assert_ne!(encode(&digest), s(wrong, "u64be"));
    assert_ne!(encode(&digest), s(wrong, "ascii"));
    assert_eq!(
        encode(&sha256(&[DS_OFFSET, &base, &1u32.to_be_bytes()])),
        s(wrong, "u32be")
    );
}

#[test]
fn v1_07_view_tag_byte() {
    let v = row(section_1(), "V1-07");
    let tag = view_tag_of(&b32(obj(v, "given"), "ss"));
    let expect = obj(v, "expect");
    assert_eq!(encode(&tag), s(expect, "view_tag"));
    let wrong = obj(v, "wrong");
    assert_ne!(encode(&tag), s(wrong, "superseded_eight_byte_width"));
    assert_ne!(encode(&tag), s(wrong, "trailing_byte_of_own_digest"));
    assert_ne!(encode(&tag), s(wrong, "leading_byte_of_H_ss"));
}

// --- §2.9 ----------------------------------------------------------------

#[test]
fn v3_01_keygen_length() {
    let v = row(section_2_9(), "V3-01");
    let lengths = u64_array(obj(v, "given"), "lengths");
    assert_eq!(lengths, [128, 96, 127]);
    let seed = v3_09_seed();
    for length in lengths {
        let length = usize::try_from(length).unwrap();
        assert_eq!(
            SchemeId3::keygen(&seed[..length]).is_ok(),
            length == SchemeId3::KEYGEN_SEED_BYTES,
            "keygen seed length {length}"
        );
    }
    let mut long = seed.clone();
    long.push(0);
    assert!(matches!(SchemeId3::keygen(&long), Err(Error::Malformed)));
}

#[test]
fn v3_02_delegation_windows() {
    let v = row(section_2_9(), "V3-02");
    let given = obj(v, "given");
    let spending = hx(given, "spending_seed");
    let planted = obj(given, "delegated_objects_by_offset");
    for offset in ["0", "5", "16", "20", "40", "47"] {
        let delegated = hx(planted, offset);
        assert_eq!(delegated.len(), 96, "offset {offset}");
        let mut seed = spending.clone();
        seed.extend_from_slice(&delegated);
        assert!(
            matches!(SchemeId3::keygen(&seed), Err(Error::SpendingKeyDelegated)),
            "offset {offset} must be rejected through SchemeId3::keygen"
        );
    }
}

#[test]
fn v3_02a_clean_keygen() {
    let v = row(section_2_9(), "V3-02a");
    let given = obj(v, "given");
    let mut seed = hx(given, "spending_seed");
    seed.extend_from_slice(&hx(given, "delegated"));
    SchemeId3::keygen(&seed).expect("no window equals spending_seed");
}

#[test]
fn v3_03_compact_viewing_rejected() {
    let sec = section_2_9();
    let given = obj(row(sec, "V3-03"), "given");
    let mut meta = hx(given, "spending_pk");
    meta.extend_from_slice(&hx(given, "viewing_pk_ec_compact_0x05"));
    meta.extend_from_slice(&v3_09_meta_bytes()[66..]);
    assert_eq!(meta.len(), 1250);
    assert!(
        SchemeId3::meta_from_bytes(&meta).is_none(),
        "0x05 viewing must fail even when spending_pk and length are well-formed"
    );
}

#[test]
fn v3_04_ecdh_is_the_x_coordinate() {
    let v = row(section_2_9(), "V3-04");
    let given = obj(v, "given");
    let ss_ec = pqsa_ec::ecdh(&b32(given, "esk"), &point(&hx(given, "viewing_pk_ec")))
        .expect("V3-04 uses a valid scalar and point");
    let expect = obj(v, "expect");
    assert_eq!(encode(&ss_ec), s(expect, "ss_ec"));
    assert_eq!(
        ss_ec.len(),
        usize::try_from(u64_field(expect, "length")).unwrap()
    );
}

#[test]
fn v3_05_combiner_ds_first() {
    let sec = section_2_9();
    let v = row(sec, "V3-05");
    let ds = s(obj(v, "given"), "domain_separator").as_bytes();
    assert_eq!(ds, DS_HYBRID);
    let ss = combine_parts(ds, obj(obj(row(sec, "V3-06"), "given"), "parts"));
    assert_eq!(encode(&ss), s(obj(v, "expect"), "ss"));
    let wrong = obj(v, "wrong");
    assert_ne!(encode(&ss), s(wrong, "appended"));
    assert_ne!(encode(&ss), s(wrong, "length_prefixed"));
}

#[test]
fn v3_06_ikm_order() {
    let v = row(section_2_9(), "V3-06");
    let parts = obj(obj(v, "given"), "parts");
    let ss = combine_parts(DS_HYBRID, parts);
    assert_eq!(encode(&ss), s(obj(v, "expect"), "ss"));
    assert_ne!(encode(&ss), s(obj(v, "wrong"), "three_field_form"));
    let swapped = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_pq"),
        &b32(parts, "ss_ec"),
        &point(&hx(parts, "epk")),
        &hx(parts, "ct"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .unwrap();
    assert_ne!(ss, swapped, "swapping the two shared secrets must move ss");
}

#[test]
fn v3_06a_ct_bound() {
    let sec = section_2_9();
    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let v = row(sec, "V3-06a");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ss_a = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(given, "ct_a"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .unwrap();
    let ss_b = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(given, "ct_b"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .unwrap();
    assert_eq!(encode(&ss_a), s(expect, "ss_a"));
    assert_eq!(encode(&ss_b), s(expect, "ss_b"));
    assert_ne!(ss_a, ss_b);
}

#[test]
fn v3_06b_viewing_bound() {
    let sec = section_2_9();
    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let v = row(sec, "V3-06b");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ss_a = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(parts, "ct"),
        &point(&hx(given, "viewing_pk_ec_a")),
        &hx(parts, "ek"),
    )
    .unwrap();
    let ss_b = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(parts, "epk")),
        &hx(parts, "ct"),
        &point(&hx(given, "viewing_pk_ec_b")),
        &hx(parts, "ek"),
    )
    .unwrap();
    assert_eq!(encode(&ss_a), s(expect, "ss_a"));
    assert_eq!(encode(&ss_b), s(expect, "ss_b"));
    assert_ne!(ss_a, ss_b);
}

#[test]
fn v3_07_epk_bound() {
    let sec = section_2_9();
    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let v = row(sec, "V3-07");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ss_a = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(given, "epk")),
        &hx(parts, "ct"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .unwrap();
    let ss_b = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &b32(parts, "ss_pq"),
        &point(&hx(given, "epk_parity_flipped")),
        &hx(parts, "ct"),
        &point(&hx(parts, "viewing_pk_ec")),
        &hx(parts, "ek"),
    )
    .unwrap();
    assert_eq!(encode(&ss_a), s(expect, "ss_a"));
    assert_eq!(encode(&ss_b), s(expect, "ss_b"));
    assert_ne!(ss_a, ss_b);
}

#[test]
fn v3_08_wire_order() {
    let v = row(section_2_9(), "V3-08");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ann = Announcement {
        epk: Some(point(&hx(given, "epk"))),
        ct: hx(given, "ct"),
        view_tag: hx(given, "view_tag")
            .try_into()
            .expect("view tag is VIEW_TAG_BYTES"),
        stealth_address: [0u8; 20],
    };
    let (_, epk_field, metadata) = SchemeId3::announcement_to_bytes(&ann);
    assert_eq!(encode(&epk_field), s(expect, "ephemeralPubKey"));
    assert_eq!(encode(&metadata), s(expect, "metadata"));
    assert_eq!(
        metadata.len(),
        usize::try_from(u64_field(expect, "metadata_bytes")).unwrap()
    );
    assert_eq!(
        epk_field.len() + metadata.len(),
        usize::try_from(u64_field(expect, "payload_bytes")).unwrap()
    );

    let reversed = hx(obj(v, "wrong"), "ct_then_view_tag");
    assert_eq!(
        reversed.len(),
        metadata.len(),
        "length does not distinguish the swap"
    );
    let parsed = SchemeId3::announcement_from_bytes(&[0u8; 20], &epk_field, &reversed)
        .expect("1089 B still parses");
    assert_ne!(
        parsed.view_tag, ann.view_tag,
        "ct || view_tag puts the tag at metadata[1088]"
    );
}

#[test]
fn v3_08a_view_tag_is_metadata_0() {
    let v = row(section_2_9(), "V3-08a");
    let metadata = hx(obj(v, "given"), "metadata");
    let parsed = SchemeId3::announcement_from_bytes(
        &[0u8; 20],
        &hx(obj(row(section_2_9(), "V3-08"), "given"), "epk"),
        &metadata,
    )
    .expect("honest shape");
    assert_eq!(
        encode(&parsed.view_tag),
        s(obj(v, "expect"), "view_tag_at_index_0")
    );
    assert_eq!(parsed.view_tag[0], metadata[0]);
    assert_ne!(
        encode(&parsed.view_tag),
        s(obj(v, "wrong"), "leading_byte_of_ct")
    );
}

#[test]
fn v3_09_keygen_matches_nist_ek() {
    let v = row(section_2_9(), "V3-09");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let (meta, master, tracking) =
        SchemeId3::keygen(&hx(given, "keygen_seed")).expect("V3-09 seed is valid");

    let nist = acvp_keygen_for_dz(&tracking.kem_seed);
    let ek = hx(nist, "ek");
    assert_eq!(
        meta.ek, ek,
        "ek is NIST's for this (d, z), not this crate's"
    );
    assert!(
        s(given, "kem_seed_source").contains(&format!("tcId {}", u64_field(nist, "tcId"))),
        "the fixture must name the ACVP case whose ek we compared"
    );

    let blob = SchemeId3::meta_to_bytes(&meta);
    assert_eq!(encode(&blob), s(expect, "meta_address"));
    assert_eq!(
        blob.len(),
        usize::try_from(u64_field(expect, "meta_address_bytes")).unwrap()
    );
    assert_eq!(&blob[66..], ek.as_slice());
    assert_eq!(encode(meta.spending.as_bytes()), s(expect, "spending_pk"));
    assert_eq!(
        encode(
            meta.viewing_ec
                .expect("schemeId 3 viewing point")
                .as_bytes()
        ),
        s(expect, "viewing_pk_ec")
    );

    let mut tracking_bytes = tracking.viewing_ec_seed.expect("schemeId 3").to_vec();
    tracking_bytes.extend_from_slice(&tracking.kem_seed);
    assert_eq!(encode(&tracking_bytes), s(expect, "tracking"));
    assert_eq!(
        tracking_bytes.len(),
        usize::try_from(u64_field(expect, "tracking_bytes")).unwrap()
    );
    assert_eq!(encode(&master.spending_seed), s(expect, "master"));
}

#[test]
fn v3_10_scalars() {
    let sec = section_2_9();
    let body = v3_09_seed();
    let halves = obj(
        obj(row(sec, "V3-10"), "given"),
        "seeds_128_B_differing_only_in_the_first_or_second_32",
    );

    let splice_spending = |half: Vec<u8>| {
        let mut seed = body.clone();
        seed[..32].copy_from_slice(&half);
        seed
    };
    let splice_viewing = |half: Vec<u8>| {
        let mut seed = body.clone();
        seed[32..64].copy_from_slice(&half);
        seed
    };

    assert!(matches!(
        SchemeId3::keygen(&splice_spending(hx(halves, "spending_seed_0"))),
        Err(Error::NoValidScalar)
    ));
    assert!(matches!(
        SchemeId3::keygen(&splice_spending(hx(halves, "spending_seed_n"))),
        Err(Error::NoValidScalar)
    ));
    SchemeId3::keygen(&splice_spending(hx(halves, "spending_seed_n_minus_1")))
        .expect("n-1 is a valid spending scalar");
    assert!(matches!(
        SchemeId3::keygen(&splice_viewing(hx(halves, "viewing_ec_seed_0"))),
        Err(Error::NoValidScalar)
    ));
}

#[test]
fn v3_11_meta_length() {
    let v = row(section_2_9(), "V3-11");
    let lengths = u64_array(obj(v, "given"), "lengths");
    assert_eq!(lengths, [1249, 1250, 1251]);
    let meta = v3_09_meta_bytes();
    assert_eq!(meta.len(), 1250);
    for length in lengths {
        let length = usize::try_from(length).unwrap();
        let mut candidate = meta.clone();
        candidate.resize(length, 0);
        assert_eq!(
            SchemeId3::meta_from_bytes(&candidate).is_some(),
            length == meta.len(),
            "meta-address length {length}"
        );
    }
}

#[test]
fn v3_12_non_point_viewing() {
    let sec = section_2_9();
    let v = row(sec, "V3-12");
    let given = obj(v, "given");
    let good = v3_09_meta_bytes();
    let mut bad = good.clone();
    bad[33..66].copy_from_slice(&hx(given, "viewing_pk_ec_nonpoint"));
    assert!(SchemeId3::meta_from_bytes(&bad).is_none());
    let mut ok = good;
    ok[33..66].copy_from_slice(&hx(given, "viewing_pk_ec_valid"));
    assert!(SchemeId3::meta_from_bytes(&ok).is_some());
}

#[test]
fn v3_13_address() {
    let v = row(section_2_9(), "V3-13");
    let addr = pqsa_ec::address_of(&point(&hx(obj(v, "given"), "stealth_pk_compressed")));
    assert_eq!(encode(&addr), s(obj(v, "expect"), "address"));
    let wrong = obj(v, "wrong");
    assert_ne!(encode(&addr), s(wrong, "keccak_of_compressed"));
    assert_ne!(encode(&addr), s(wrong, "keccak_with_0x04_prefix"));
    assert_ne!(encode(&addr), s(wrong, "first_20_bytes_not_last_20"));
}

#[test]
fn v3_14_tag_mismatch_is_a_skip() {
    let sec = section_2_9();
    let v = row(sec, "V3-14");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let tc_id = u64_field(given, "acvp_decapsulation_tcId");
    let acvp_case = obj(acvp(), "decapsulation")
        .as_array()
        .expect("ACVP decapsulation is an array")
        .iter()
        .find(|case| u64_field(case, "tcId") == tc_id)
        .expect("V3-14 ACVP case exists");
    assert_eq!(s(acvp_case, "reason"), s(given, "acvp_reason"));

    let ann_g = obj(given, "announcement");
    let ct = hx(ann_g, "ct");
    assert_eq!(ct, hx(acvp_case, "c"), "ciphertext comes from tcId {tc_id}");
    let ss_pq = b32(expect, "ss_pq");
    assert_eq!(ss_pq.as_slice(), hx(acvp_case, "k"));

    let dk = hx(acvp_case, "dk");
    assert_eq!(dk.len(), 2400);
    let ek = &dk[1152..2336];
    assert_eq!(ek, hx(given, "ek"));
    assert_eq!(Sha3_256::digest(ek).as_slice(), &dk[2336..2368]);

    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let epk = point(&hx(ann_g, "ephemeralPubKey"));
    assert_eq!(epk.as_bytes(), point(&hx(parts, "epk")).as_bytes());
    let viewing = point(&hx(parts, "viewing_pk_ec"));
    let ss = combine_secrets(
        DS_HYBRID,
        &b32(parts, "ss_ec"),
        &ss_pq,
        &epk,
        &ct,
        &viewing,
        ek,
    )
    .unwrap();
    assert_eq!(encode(&ss), s(expect, "ss"));

    let derived_tag = view_tag_of(&ss);
    assert_eq!(encode(&derived_tag), s(expect, "derived_view_tag"));
    let announced_tag: [u8; VIEW_TAG_BYTES] = hx(ann_g, "view_tag").try_into().unwrap();
    assert_ne!(announced_tag, derived_tag);

    let spending = point(&hx(obj(row(sec, "V3-09"), "expect"), "spending_pk"));
    let (offset, _) = derive_from_shared_secret(&ss).unwrap();
    let stealth = add_points(&spending, &offset).unwrap();
    let address = pqsa_ec::address_of(&stealth);
    assert!(
        match_from_secret(&ss, &spending, &derived_tag, &address).is_some(),
        "positive control: the secret, tag and address match"
    );
    assert!(
        match_from_secret(&ss, &spending, &announced_tag, &address).is_none(),
        "changing only the announced tag must turn the match into a skip"
    );
}

#[test]
fn v3_15_announcement_shape() {
    let sec = section_2_9();
    let v = row(sec, "V3-15");
    let given = obj(v, "given");
    let epk_lengths = u64_array(given, "ephemeralPubKey_lengths");
    let metadata_lengths = u64_array(given, "metadata_lengths");
    assert_eq!(epk_lengths, [32, 33]);
    assert_eq!(metadata_lengths, [1088, 1089, 1090]);
    let honest_epk = hx(obj(row(sec, "V3-08"), "given"), "epk");
    let honest_md = hx(obj(row(sec, "V3-08"), "expect"), "metadata");
    assert_eq!(honest_epk.len(), 33);
    assert_eq!(honest_md.len(), VIEW_TAG_BYTES + MlKem768::CT_BYTES);

    for epk_len in epk_lengths {
        for &md_len in &metadata_lengths {
            let epk_len = usize::try_from(epk_len).unwrap();
            let md_len = usize::try_from(md_len).unwrap();
            let epk = if epk_len == 33 {
                honest_epk.clone()
            } else {
                vec![0x02; epk_len]
            };
            let md = if md_len == honest_md.len() {
                honest_md.clone()
            } else {
                vec![0x11; md_len]
            };
            let parsed = SchemeId3::announcement_from_bytes(&[0u8; 20], &epk, &md);
            let want_some = epk_len == 33 && md_len == 1089;
            assert_eq!(
                parsed.is_some(),
                want_some,
                "epk {epk_len} metadata {md_len}"
            );
        }
    }
}
