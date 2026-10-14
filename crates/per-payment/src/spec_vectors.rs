//! Spec vectors from `vectors/section-*.json`.
//!
//! Expected bytes come from the committed fixtures, not from this implementation.
//! `check_offset` is crate-private; this module stays under `src/` so it can call it.

use super::*;
use pqsa_core::{Bytes32, Error, StealthScheme, VIEW_TAG_BYTES};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const SECTION_1: &str = include_str!("../../../vectors/section-1.json");
const SECTION_2: &str = include_str!("../../../vectors/section-2.json");
const ACVP: &str = include_str!("../../../vectors/tier1/ml-kem-768-acvp.json");

// V1-06 is withdrawn: §1 no longer retries with a counter.
const SECTION_1_CASES: &[&str] = &["V1-01", "V1-02", "V1-03", "V1-04", "V1-05", "V1-07"];
const SECTION_2_CASES: &[&str] = &[
    "V3-01", "V3-02", "V3-02a", "V3-03", "V3-04", "V3-05", "V3-06", "V3-06a", "V3-06b", "V3-07",
    "V3-08", "V3-08a", "V3-09", "V3-10", "V3-11", "V3-12", "V3-13", "V3-14", "V3-15", "V3-16",
    "V3-17", "V3-18", "V3-19",
];

fn parse(raw: &str) -> Value {
    serde_json::from_slice(raw.as_bytes()).expect("committed fixture is JSON")
}

fn section_1() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(SECTION_1))
}

fn section_2() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(SECTION_2))
}

fn acvp() -> &'static Value {
    static DOC: OnceLock<Value> = OnceLock::new();
    DOC.get_or_init(|| parse(ACVP))
}

fn acvp_case(section: &str, tc_id: u64) -> &'static Value {
    obj(acvp(), section)
        .as_array()
        .unwrap_or_else(|| panic!("ACVP {section} is an array"))
        .iter()
        .find(|case| u64_field(case, "tcId") == tc_id)
        .unwrap_or_else(|| panic!("no ACVP {section} case has tcId {tc_id}"))
}

/// `ek` out of an ACVP decapsulation case's 2 400-byte expanded `dk`: FIPS 203 puts it at
/// `dk[1152..2336]`, followed by `H(ek)`.
fn acvp_ek_of_expanded_dk(case: &Value) -> Vec<u8> {
    let dk = hx(case, "dk");
    assert_eq!(dk.len(), 2400, "expanded dk");
    let ek = &dk[1152..2336];
    assert_eq!(Sha3_256::digest(ek).as_slice(), &dk[2336..2368], "H(ek)");
    ek.to_vec()
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

fn address(v: &Value, key: &str) -> [u8; 20] {
    hx(v, key)
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{key} is {} bytes, not 20", b.len()))
}

fn b32(v: &Value, key: &str) -> Bytes32 {
    hx(v, key)
        .try_into()
        .unwrap_or_else(|b: Vec<u8>| panic!("{key} is {} bytes, not 32", b.len()))
}

fn point(bytes: &[u8]) -> pqsa_ec::CompressedPoint {
    pqsa_ec::decode_point(bytes).expect("fixture point is SEC1 compressed")
}

fn encode<T: AsRef<[u8]> + ?Sized>(bytes: &T) -> String {
    hex::encode(bytes.as_ref())
}

fn sha256(parts: &[&[u8]]) -> Bytes32 {
    Sha256::digest(parts.concat()).into()
}

/// `bytes` cut to `len`, or padded to it with `0x11`, as the generator does.
fn resized(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.resize(len, 0x11);
    out
}

fn v3_09_seed() -> Vec<u8> {
    hx(obj(row(section_2(), "V3-09"), "given"), "keygen_seed")
}

fn v3_09_meta_bytes() -> Vec<u8> {
    hx(obj(row(section_2(), "V3-09"), "expect"), "meta_address")
}

fn v3_09_point(key: &str) -> pqsa_ec::CompressedPoint {
    point(&hx(obj(row(section_2(), "V3-09"), "expect"), key))
}

/// §2.8's `checkStealthAddress` with V3-09's keys, as `viewingKey` and `spendingPubKey`.
fn v3_09_check(stealth_address: &[u8; 20], ephemeral_pub_key: &[u8]) -> Result<bool, Error> {
    let expect = obj(row(section_2(), "V3-09"), "expect");
    erc5564::check_stealth_address(
        stealth_address,
        ephemeral_pub_key,
        &hx(expect, "tracking"),
        &hx(expect, "spending_pk"),
    )
}

fn combine_parts(ds: &[u8], parts: &Value) -> Zeroizing<Bytes32> {
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
fn vector_ids_match_inventory() {
    assert_eq!(
        vector_ids(section_1()),
        SECTION_1_CASES.iter().copied().collect()
    );
    assert_eq!(
        vector_ids(section_2()),
        SECTION_2_CASES.iter().copied().collect()
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
    let (offset, _) = derive_from_shared_secret(&ss).expect("this base is in range");
    assert_eq!(encode(&offset), s(expect, "offset"));
    assert_eq!(*offset, base, "the offset is base itself");
}

#[test]
fn v1_02_digest_is_big_endian() {
    let v = row(section_1(), "V1-02");
    let given = obj(v, "given");
    let base = b32(given, "base");
    let offset = check_offset(base.into()).expect("this base is already a valid scalar");
    assert_eq!(encode(&offset), s(obj(v, "expect"), "offset_big_endian"));
    assert_ne!(
        encode(&offset),
        s(obj(v, "wrong"), "offset_little_endian"),
        "little-endian read of the same digest is a different scalar"
    );
}

#[test]
fn v1_03_base_zero_fails() {
    let v = row(section_1(), "V1-03");
    let base = b32(obj(v, "given"), "base");
    assert_eq!(s(obj(v, "expect"), "outcome"), "fail");
    assert!(matches!(
        check_offset(base.into()),
        Err(Error::NoValidScalar)
    ));
    assert_eq!(s(obj(v, "wrong"), "offset"), encode(&[0u8; 32]));
}

#[test]
fn v1_04_base_n_fails() {
    let v = row(section_1(), "V1-04");
    let base = b32(obj(v, "given"), "base");
    assert_eq!(s(obj(v, "expect"), "outcome"), "fail");
    assert!(
        matches!(check_offset(base.into()), Err(Error::NoValidScalar)),
        "n is not a valid scalar; a silent reduce-mod-n would yield 0"
    );
}

#[test]
fn v1_05_n_minus_1_accepted() {
    let v = row(section_1(), "V1-05");
    let base = b32(obj(v, "given"), "base");
    let offset = check_offset(base.into()).expect("n-1 is a valid scalar");
    assert_eq!(encode(&offset), s(obj(v, "expect"), "offset"));
    assert_eq!(*offset, base);
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

// --- §2 ------------------------------------------------------------------

#[test]
fn v3_01_keygen_length() {
    let v = row(section_2(), "V3-01");
    let given = obj(v, "given");
    let lengths = u64_array(given, "lengths");
    assert_eq!(lengths, [128, 96, 127]);
    let seed = v3_09_seed();
    let seeds = obj(given, "seeds");
    for length in lengths {
        let length = usize::try_from(length).unwrap();
        let candidate = hx(seeds, &length.to_string());
        assert_eq!(
            candidate.as_slice(),
            &seed[..length],
            "a prefix of V3-09's seed"
        );
        assert_eq!(
            SchemeId3::keygen(&candidate).is_ok(),
            length == SchemeId3::KEYGEN_SEED_BYTES,
            "keygen seed length {length}"
        );
    }
    let mut long = seed.clone();
    long.push(0);
    assert!(matches!(SchemeId3::keygen(&long), Err(Error::Malformed)));
}

#[test]
fn v3_02_delegation_components() {
    let v = row(section_2(), "V3-02");
    let given = obj(v, "given");
    let spending = hx(given, "spending_seed");
    let planted = obj(given, "delegated_objects_by_component");
    for component in ["viewing_ec_seed", "d", "z"] {
        let delegated = hx(planted, component);
        assert_eq!(delegated.len(), 96, "{component}");
        let mut seed = spending.clone();
        seed.extend_from_slice(&delegated);
        assert!(
            matches!(SchemeId3::keygen(&seed), Err(Error::SpendingKeyDelegated)),
            "spending_seed copied into {component} must be rejected through SchemeId3::keygen"
        );
    }
}

#[test]
fn v3_02a_clean_keygen() {
    let v = row(section_2(), "V3-02a");
    let given = obj(v, "given");
    let mut seed = hx(given, "spending_seed");
    seed.extend_from_slice(&hx(given, "delegated"));
    SchemeId3::keygen(&seed).expect("no component equals spending_seed");
}

#[test]
fn v3_03_compact_viewing_rejected() {
    let sec = section_2();
    let given = obj(row(sec, "V3-03"), "given");
    let mut meta = hx(given, "spending_pk");
    meta.extend_from_slice(&hx(given, "viewing_pk_ec_compact_0x05"));
    meta.extend_from_slice(&v3_09_meta_bytes()[66..]);
    assert_eq!(meta.len(), 1250);
    assert_eq!(meta, hx(given, "meta_address"));
    assert!(
        SchemeId3::meta_from_bytes(&hx(given, "meta_address")).is_none(),
        "0x05 viewing must fail even when spending_pk and length are well-formed"
    );
}

#[test]
fn v3_04_ecdh_is_the_x_coordinate() {
    let v = row(section_2(), "V3-04");
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
    let sec = section_2();
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
    let v = row(section_2(), "V3-06");
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

    // Where the parts come from.
    let given = obj(v, "given");
    let esk = b32(given, "esk");
    let viewing = point(&hx(parts, "viewing_pk_ec"));
    assert_eq!(viewing, v3_09_point("viewing_pk_ec"));
    assert_eq!(pqsa_ec::public_point(&esk), Ok(point(&hx(parts, "epk"))));
    assert_eq!(*pqsa_ec::ecdh(&esk, &viewing).unwrap(), b32(parts, "ss_ec"));
    let nist = acvp_case("encapsulation", u64_field(given, "acvp_encapsulation_tcId"));
    let (ek, m) = (hx(parts, "ek"), hx(given, "m"));
    assert_eq!(ek, hx(nist, "ek"));
    assert_eq!(m, hx(nist, "m"));
    let (ct, ss_pq) = MlKem768::encapsulate(&ek, &m).expect("NIST's ek");
    assert_eq!(ct, hx(parts, "ct"));
    assert_eq!(*ss_pq, b32(parts, "ss_pq"));
}

#[test]
fn v3_06a_ct_bound() {
    let sec = section_2();
    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let v = row(sec, "V3-06a");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    assert_eq!(hx(given, "ct_a"), hx(parts, "ct"));
    let ct_b = hx(given, "ct_b");
    let nist = obj(acvp(), "encapsulation")
        .as_array()
        .expect("ACVP encapsulation is an array")
        .iter()
        .find(|case| hx(case, "c") == ct_b)
        .expect("ct_b is an ACVP ciphertext");
    assert!(
        s(given, "ct_b_is").ends_with(&format!("tcId {}", u64_field(nist, "tcId"))),
        "the fixture must name the ACVP case ct_b came from"
    );
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
    let sec = section_2();
    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let v = row(sec, "V3-06b");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    assert_eq!(hx(given, "viewing_pk_ec_a"), hx(parts, "viewing_pk_ec"));
    assert_eq!(
        pqsa_ec::public_point(&b32(given, "viewing_ec_b")),
        Ok(point(&hx(given, "viewing_pk_ec_b")))
    );
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
    let sec = section_2();
    let parts = obj(obj(row(sec, "V3-06"), "given"), "parts");
    let v = row(sec, "V3-07");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let (epk, flipped) = (hx(given, "epk"), hx(given, "epk_parity_flipped"));
    assert_eq!(epk, hx(parts, "epk"));
    assert_eq!(epk[1..], flipped[1..], "only the parity tag differs");
    assert_ne!(epk[0], flipped[0]);
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
    let v = row(section_2(), "V3-08");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ann = Announcement::new(
        point(&hx(given, "epk")),
        hx(given, "ct"),
        hx(given, "view_tag")
            .try_into()
            .expect("view tag is VIEW_TAG_BYTES"),
        [0u8; 20],
    )
    .unwrap();
    let (_, epk_field, metadata) = SchemeId3::announcement_to_bytes(&ann);
    assert_eq!(encode(&epk_field), s(expect, "ephemeralPubKey"));
    assert_eq!(encode(&metadata), s(expect, "metadata"));
    assert_eq!(
        epk_field.len(),
        usize::try_from(u64_field(expect, "ephemeralPubKey_bytes")).unwrap()
    );
    assert_eq!(
        epk_field.len() + metadata.len(),
        usize::try_from(u64_field(expect, "payload_bytes")).unwrap()
    );

    let wrong = obj(v, "wrong");
    let reversed = hx(wrong, "ct_then_epk");
    assert_eq!(
        reversed.len(),
        epk_field.len(),
        "length does not distinguish the swap"
    );
    if let Some(parsed) = SchemeId3::announcement_from_bytes(&[0u8; 20], &reversed, &metadata) {
        assert_ne!(
            parsed.epk, ann.epk,
            "ct || epk puts ct's first 33 bytes where epk belongs"
        );
    }
    let superseded = obj(wrong, "superseded");
    assert!(
        SchemeId3::announcement_from_bytes(
            &[0u8; 20],
            &hx(superseded, "ephemeralPubKey"),
            &hx(superseded, "metadata"),
        )
        .is_none(),
        "ct in metadata leaves a 33-byte ephemeralPubKey, which is a skip"
    );
}

#[test]
fn v3_08a_view_tag_is_metadata_0() {
    let v = row(section_2(), "V3-08a");
    let given = obj(v, "given");
    let epk_field = hx(given, "ephemeralPubKey");
    let want = s(obj(v, "expect"), "view_tag_at_index_0");
    for key in ["metadata_view_tag_only", "metadata_with_token_block"] {
        let metadata = hx(given, key);
        let parsed = SchemeId3::announcement_from_bytes(&[0u8; 20], &epk_field, &metadata)
            .unwrap_or_else(|| panic!("{key} is an honest shape"));
        assert_eq!(encode(&parsed.view_tag), want, "{key}");
        assert_eq!(parsed.view_tag[0], metadata[0], "{key}");
    }
    let with_token = hx(given, "metadata_with_token_block");
    assert_eq!(with_token.len(), VIEW_TAG_BYTES + 56);
    assert_eq!(
        encode(&with_token[with_token.len() - 1..]),
        s(obj(v, "wrong"), "last_byte_of_metadata")
    );
    assert_ne!(s(obj(v, "wrong"), "last_byte_of_metadata"), want);
}

#[test]
fn v3_09_keygen_matches_nist_ek() {
    let v = row(section_2(), "V3-09");
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
        encode(meta.viewing_ec.as_bytes()),
        s(expect, "viewing_pk_ec")
    );

    let mut tracking_bytes = tracking.viewing_ec_seed.expect("schemeId 3").to_vec();
    tracking_bytes.extend_from_slice(&tracking.kem_seed);
    assert_eq!(encode(&tracking_bytes), s(expect, "tracking"));
    assert_eq!(
        tracking_bytes.len(),
        usize::try_from(u64_field(expect, "tracking_bytes")).unwrap()
    );
    assert_eq!(tracking_bytes.len(), erc5564::VIEWING_KEY_BYTES);
    assert_eq!(encode(&master.spending_seed), s(expect, "master"));
}

#[test]
fn v3_10_scalars() {
    let body = v3_09_seed();
    let seeds = obj(obj(row(section_2(), "V3-10"), "given"), "seeds");
    let n = hx(obj(row(section_1(), "V1-04"), "given"), "base");
    let n_minus_1 = hx(obj(row(section_1(), "V1-05"), "given"), "base");

    // Each seed is V3-09's with one 32-byte half replaced.
    let seed = |key: &str, at: usize, half: &[u8]| {
        let seed = hx(seeds, key);
        assert_eq!(seed.len(), body.len(), "{key}");
        assert_eq!(&seed[at..at + 32], half, "{key}");
        assert_eq!(seed[..at], body[..at], "{key}");
        assert_eq!(seed[at + 32..], body[at + 32..], "{key}");
        seed
    };

    assert!(matches!(
        SchemeId3::keygen(&seed("spending_seed_0", 0, &[0; 32])),
        Err(Error::NoValidScalar)
    ));
    assert!(matches!(
        SchemeId3::keygen(&seed("spending_seed_n", 0, &n)),
        Err(Error::NoValidScalar)
    ));
    SchemeId3::keygen(&seed("spending_seed_n_minus_1", 0, &n_minus_1))
        .expect("n-1 is a valid spending scalar");
    assert!(matches!(
        SchemeId3::keygen(&seed("viewing_ec_seed_0", 32, &[0; 32])),
        Err(Error::NoValidScalar)
    ));
}

#[test]
fn v3_11_meta_length() {
    let v = row(section_2(), "V3-11");
    let given = obj(v, "given");
    let lengths = u64_array(given, "lengths");
    assert_eq!(lengths, [1249, 1250, 1251]);
    let meta = v3_09_meta_bytes();
    assert_eq!(meta.len(), 1250);
    let candidates = obj(given, "meta_addresses");
    for length in lengths {
        let length = usize::try_from(length).unwrap();
        let mut expected = meta.clone();
        expected.resize(length, 0);
        let candidate = hx(candidates, &length.to_string());
        assert_eq!(candidate, expected, "meta-address length {length}");
        assert_eq!(
            SchemeId3::meta_from_bytes(&candidate).is_some(),
            length == meta.len(),
            "meta-address length {length}"
        );
    }
}

#[test]
fn v3_12_non_point_viewing() {
    let v = row(section_2(), "V3-12");
    let given = obj(v, "given");
    let good = v3_09_meta_bytes();
    let mut bad = good.clone();
    bad[33..66].copy_from_slice(&hx(given, "viewing_pk_ec_nonpoint"));
    assert_eq!(bad, hx(given, "meta_address_nonpoint"));
    assert!(SchemeId3::meta_from_bytes(&hx(given, "meta_address_nonpoint")).is_none());
    let mut ok = good;
    ok[33..66].copy_from_slice(&hx(given, "viewing_pk_ec_valid"));
    assert_eq!(ok, hx(given, "meta_address_valid"));
    assert!(SchemeId3::meta_from_bytes(&hx(given, "meta_address_valid")).is_some());
}

#[test]
fn v3_13_address() {
    let sec = section_2();
    let v = row(sec, "V3-13");
    let given = obj(v, "given");
    let stealth = point(&hx(given, "stealth_pk_compressed"));
    let addr = pqsa_ec::address_of(&stealth);
    assert_eq!(encode(&addr), s(obj(v, "expect"), "address"));
    let wrong = obj(v, "wrong");
    assert_ne!(encode(&addr), s(wrong, "keccak_of_compressed"));
    assert_ne!(encode(&addr), s(wrong, "keccak_with_0x04_prefix"));
    assert_ne!(encode(&addr), s(wrong, "first_20_bytes_not_last_20"));

    // The uncompressed form is the same point, and hashing it without its prefix is the address.
    let uncompressed = hx(given, "stealth_pk_uncompressed");
    assert_eq!(uncompressed.len(), 65);
    assert_eq!(uncompressed[0], 0x04);
    assert_eq!(uncompressed[1..33], stealth.as_bytes()[1..]);
    assert_eq!(stealth.as_bytes()[0], 0x02 | (uncompressed[64] & 1));
    assert_eq!(Keccak256::digest(&uncompressed[1..])[12..], addr);

    // Where stealth_pk comes from.
    let from = obj(given, "stealth_pk_from");
    let source = row(sec, s(from, "row"));
    assert_eq!(
        s(from, "spending_pk"),
        s(obj(source, "given"), "spending_pk")
    );
    assert_eq!(s(from, "ss"), s(obj(source, "given"), "ss"));
    let offset = offset_of(&b32(from, "ss")).expect("V3-16's H(ss) is in range");
    assert_eq!(
        add_points(&point(&hx(from, "spending_pk")), &offset),
        Some(stealth)
    );
}

#[test]
fn v3_14_tag_mismatch_is_a_skip() {
    let v = row(section_2(), "V3-14");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let tc_id = u64_field(given, "acvp_decapsulation_tcId");
    let acvp_case = acvp_case("decapsulation", tc_id);
    assert_eq!(s(acvp_case, "reason"), s(given, "acvp_reason"));

    let ann_g = obj(given, "announcement");
    let announced_address = address(ann_g, "stealthAddress");
    let epk_field = hx(ann_g, "ephemeralPubKey");
    let metadata = hx(ann_g, "metadata");
    assert_eq!(epk_field.len(), EPHEMERAL_PUB_KEY_BYTES);
    assert_eq!(metadata.len(), VIEW_TAG_BYTES);
    let ann = SchemeId3::announcement_from_bytes(&announced_address, &epk_field, &metadata)
        .expect("V3-14 has a valid wire shape; only its view tag is wrong");
    let ct = ann.ct();
    assert_eq!(ct, hx(acvp_case, "c"), "ciphertext comes from tcId {tc_id}");
    // This ACVP case has no (d, z) seed; use its published ss_pq.
    let ss_pq = b32(expect, "ss_pq");
    assert_eq!(ss_pq.as_slice(), hx(acvp_case, "k"));
    let ek = acvp_ek_of_expanded_dk(acvp_case);
    assert_eq!(ek, hx(given, "ek"));

    let epk = ann.epk;
    let viewing_ec = b32(given, "viewing_ec");
    let viewing = point(&hx(given, "viewing_pk_ec"));
    assert_eq!(pqsa_ec::public_point(&viewing_ec), Ok(viewing));
    assert_eq!(viewing, v3_09_point("viewing_pk_ec"));
    let ss_ec = pqsa_ec::ecdh(&viewing_ec, &epk).expect("valid scalar and point");
    assert_eq!(encode(&ss_ec), s(expect, "ss_ec"));
    let ss = combine_secrets(DS_HYBRID, &ss_ec, &ss_pq, &epk, ct, &viewing, &ek).unwrap();
    assert_eq!(encode(&ss), s(expect, "ss"));

    let derived_tag = view_tag_of(&ss);
    assert_eq!(encode(&derived_tag), s(expect, "derived_view_tag"));
    assert_ne!(ann.view_tag, derived_tag);

    let spending = point(&hx(given, "spending_pk"));
    assert_eq!(spending, v3_09_point("spending_pk"));
    let (offset, _) = derive_from_shared_secret(&ss).unwrap();
    let stealth = add_points(&spending, &offset).unwrap();
    assert_eq!(pqsa_ec::address_of(&stealth), ann.stealth_address);
    assert_eq!(s(expect, "outcome"), "skip");
    assert!(
        match_from_secret(&ss, &spending, &ann.view_tag, &ann.stealth_address).is_none(),
        "changing only the announced tag must turn the match into a skip"
    );

    let corrected =
        SchemeId3::announcement_from_bytes(&announced_address, &epk_field, &derived_tag)
            .expect("correcting the tag must preserve the valid wire shape");
    assert_eq!(corrected.epk, ann.epk);
    assert_eq!(corrected.ct(), ann.ct());
    assert_eq!(corrected.stealth_address, ann.stealth_address);
    assert_eq!(s(expect, "outcome_with_derived_view_tag"), "match");
    let found = match_from_secret(
        &ss,
        &spending,
        &corrected.view_tag,
        &corrected.stealth_address,
    )
    .expect("positive control: the secret, tag and announced address match");
    assert_eq!(found.stealth_address, announced_address);
    assert_eq!(found.shared_secret, ss);
}

#[test]
fn v3_15_announcement_shape() {
    let sec = section_2();
    let v = row(sec, "V3-15");
    let given = obj(v, "given");
    let epk_lengths = u64_array(given, "ephemeralPubKey_lengths");
    let metadata_lengths = u64_array(given, "metadata_lengths");
    assert_eq!(epk_lengths, [33, 1120, 1121, 1122]);
    assert_eq!(metadata_lengths, [0, 1, 57]);
    let honest_epk = hx(obj(row(sec, "V3-08"), "expect"), "ephemeralPubKey");
    let honest_md = hx(obj(row(sec, "V3-08"), "expect"), "metadata");
    assert_eq!(honest_epk.len(), EPHEMERAL_PUB_KEY_BYTES);
    assert_eq!(honest_md.len(), VIEW_TAG_BYTES);
    let epks = obj(given, "ephemeralPubKeys");
    let mds = obj(given, "metadatas");

    for epk_len in epk_lengths {
        for &md_len in &metadata_lengths {
            // A truncated or extended field keeps the honest bytes it has room for, so the
            // only thing wrong with it is its length.
            let epk = hx(epks, &epk_len.to_string());
            let md = hx(mds, &md_len.to_string());
            let epk_len = usize::try_from(epk_len).unwrap();
            let md_len = usize::try_from(md_len).unwrap();
            assert_eq!(
                epk,
                resized(&honest_epk, epk_len),
                "ephemeralPubKey {epk_len}"
            );
            assert_eq!(md, resized(&honest_md, md_len), "metadata {md_len}");
            let parsed = SchemeId3::announcement_from_bytes(&[0u8; 20], &epk, &md);
            let want_some = epk_len == EPHEMERAL_PUB_KEY_BYTES && md_len >= VIEW_TAG_BYTES;
            assert_eq!(
                parsed.is_some(),
                want_some,
                "ephemeralPubKey {epk_len} metadata {md_len}"
            );
            // §2.8: no metadata goes in, and a skip is `false`, not an error.
            assert_eq!(
                v3_09_check(&[0u8; 20], &epk),
                Ok(false),
                "ephemeralPubKey {epk_len}"
            );
        }
    }
}

#[test]
fn v3_16_stealth_key_pair() {
    let sec = section_2();
    let v = row(sec, "V3-16");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let ss = b32(given, "ss");
    assert_eq!(
        encode(&ss),
        s(obj(row(sec, s(given, "ss_from")), "expect"), "ss")
    );
    let spending_sk = b32(given, "spending_sk");
    let spending = pqsa_ec::public_point(&spending_sk).expect("valid scalar");
    assert_eq!(encode(spending.as_bytes()), s(given, "spending_pk"));
    assert_eq!(spending, v3_09_point("spending_pk"));

    let offset = offset_of(&ss).expect("this H(ss) is in range");
    assert_eq!(encode(&offset), s(expect, "H_ss"));
    let stealth = add_points(&spending, &offset).unwrap();
    assert_eq!(encode(stealth.as_bytes()), s(expect, "stealth_pk"));
    let stealth_address = pqsa_ec::address_of(&stealth);
    assert_eq!(encode(&stealth_address), s(expect, "address"));

    // The recipient's side, through the public API. spend_key checks the key controls the address.
    let spend = |spending_seed: Bytes32, stealth_address: [u8; 20]| {
        SchemeId3::spend_key(
            &Master {
                spending_seed: spending_seed.into(),
                viewing_ec_seed: None,
                kem_seed: Vec::new().into(),
            },
            &Match {
                stealth_address,
                shared_secret: ss.into(),
            },
        )
    };
    let stealth_sk = spend(spending_sk, stealth_address).expect("one key pair");
    assert_eq!(
        encode(SchemeId3::spend_key_bytes(&stealth_sk)),
        s(expect, "stealth_sk")
    );
    assert_eq!(
        pqsa_ec::public_point(stealth_sk.expose_secret()),
        Ok(stealth)
    );

    // spending_sk + H(ss) passes n, so the reduction is mod n.
    let near_n = obj(expect, "near_n");
    let sk_near_n = b32(given, "spending_sk_near_n");
    assert_eq!(
        encode(&sk_near_n),
        s(obj(row(section_1(), "V1-05"), "given"), "base"),
        "n - 1"
    );
    let spending_near_n = pqsa_ec::public_point(&sk_near_n).expect("n - 1 is a valid scalar");
    let stealth_near_n = add_points(&spending_near_n, &offset).unwrap();
    assert_eq!(encode(stealth_near_n.as_bytes()), s(near_n, "stealth_pk"));
    let address_near_n = pqsa_ec::address_of(&stealth_near_n);
    let sk = spend(sk_near_n, address_near_n).expect("one key pair");
    assert_eq!(
        encode(SchemeId3::spend_key_bytes(&sk)),
        s(near_n, "stealth_sk")
    );
    assert_eq!(
        pqsa_ec::public_point(sk.expose_secret()),
        Ok(stealth_near_n)
    );

    let wrong = obj(v, "wrong");
    for key in ["multiplicative_stealth_pk", "ss_as_offset_stealth_pk"] {
        assert_ne!(s(wrong, key), s(expect, "stealth_pk"), "{key}");
    }
    assert_ne!(
        s(wrong, "multiplicative_stealth_sk"),
        s(expect, "stealth_sk")
    );
    let reduced = b32(wrong, "near_n_reduced_mod_2_256");
    assert_ne!(&reduced, sk.expose_secret());
    let reduced_pk = pqsa_ec::public_point(&reduced).expect("a valid scalar, for another address");
    assert_ne!(pqsa_ec::address_of(&reduced_pk), address_near_n);
}

#[test]
fn v3_17_the_address_decides() {
    let v = row(section_2(), "V3-17");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let nist = acvp_case("decapsulation", u64_field(given, "acvp_decapsulation_tcId"));
    assert_eq!(s(nist, "reason"), s(given, "acvp_reason"));
    let ek = acvp_ek_of_expanded_dk(nist);
    assert_eq!(ek, hx(given, "ek"));

    let ann_g = obj(given, "announcement");
    let epk_field = hx(ann_g, "ephemeralPubKey");
    let metadata = hx(ann_g, "metadata");
    let honest_address = address(given, "stealthAddress_honest");
    let lie_address = address(given, "stealthAddress_lie");
    let honest = SchemeId3::announcement_from_bytes(&honest_address, &epk_field, &metadata)
        .expect("well-formed");
    let lie = SchemeId3::announcement_from_bytes(&lie_address, &epk_field, &metadata)
        .expect("well-formed");
    assert_eq!(honest.ct, hx(nist, "c"), "ct is NIST's");
    let ss_pq = b32(expect, "ss_pq");
    assert_eq!(ss_pq.as_slice(), hx(nist, "k"));

    let epk = honest.epk;
    let viewing_ec = b32(given, "viewing_ec");
    let viewing = point(&hx(given, "viewing_pk_ec"));
    assert_eq!(pqsa_ec::public_point(&viewing_ec), Ok(viewing));
    let ss_ec = pqsa_ec::ecdh(&viewing_ec, &epk).expect("valid scalar and point");
    assert_eq!(encode(&ss_ec), s(expect, "ss_ec"));
    let ss = combine_secrets(DS_HYBRID, &ss_ec, &ss_pq, &epk, &honest.ct, &viewing, &ek).unwrap();
    assert_eq!(encode(&ss), s(expect, "ss"));
    assert_eq!(encode(&view_tag_of(&ss)), s(expect, "view_tag"));
    assert_eq!(honest.view_tag, view_tag_of(&ss));
    assert_eq!(lie.view_tag, honest.view_tag, "the tag passes in both");

    let spending = point(&hx(given, "spending_pk"));
    let stealth = add_points(&spending, &offset_of(&ss).unwrap()).unwrap();
    assert_eq!(encode(stealth.as_bytes()), s(expect, "stealth_pk"));
    assert_eq!(encode(&pqsa_ec::address_of(&stealth)), s(expect, "address"));
    assert_eq!(pqsa_ec::address_of(&stealth), honest_address);

    assert!(s(expect, "honest").starts_with("match"));
    let found = match_from_secret(&ss, &spending, &honest.view_tag, &honest.stealth_address)
        .expect("the honest announcement is a match");
    assert_eq!(found.stealth_address, honest_address);
    assert_eq!(found.shared_secret, ss);
    assert_eq!(s(expect, "lie"), "skip");
    assert!(
        match_from_secret(&ss, &spending, &lie.view_tag, &lie.stealth_address).is_none(),
        "the same tag with another stealthAddress is a skip"
    );
}

#[test]
fn v3_18_a_non_point_epk_is_a_skip() {
    let sec = section_2();
    let v = row(sec, "V3-18");
    let given = obj(v, "given");
    let v3_08 = obj(row(sec, "V3-08"), "expect");
    let metadata = hx(given, "metadata");
    assert_eq!(metadata, hx(v3_08, "metadata"));
    let honest = hx(given, "honest_ephemeralPubKey");
    assert_eq!(honest, hx(v3_08, "ephemeralPubKey"));
    assert!(
        SchemeId3::announcement_from_bytes(&[0u8; 20], &honest, &metadata).is_some(),
        "positive control"
    );

    let entries = obj(given, "ephemeralPubKeys");
    let names = entries
        .as_object()
        .expect("ephemeralPubKeys is an object")
        .keys();
    assert_eq!(names.len(), 5);
    for name in names {
        let field = hx(entries, name);
        assert_eq!(
            field.len(),
            EPHEMERAL_PUB_KEY_BYTES,
            "{name}: the length passes"
        );
        assert_eq!(field[33..], honest[33..], "{name}: V3-08's ct");
        assert!(pqsa_ec::decode_point(&field[..33]).is_err(), "{name}");
        assert!(
            SchemeId3::announcement_from_bytes(&[0u8; 20], &field, &metadata).is_none(),
            "{name} is a skip"
        );
        assert_eq!(v3_09_check(&[0u8; 20], &field), Ok(false), "{name}");
    }

    // A decoder that reduced x mod p would read x = p + 1 as this point.
    let mut x_1 = [0u8; 33];
    x_1[0] = 0x02;
    x_1[32] = 1;
    pqsa_ec::decode_point(&x_1).expect("x = 1 is on the curve");
}

/// FIPS 203 `ByteDecode_12`: the first coefficient of `ek`'s vector part that is not below `q`.
fn first_coefficient_at_least_q(ek: &[u8], q: u16) -> Option<(usize, u16)> {
    ek[..1152]
        .chunks_exact(3)
        .flat_map(|b| {
            let (b0, b1, b2) = (u16::from(b[0]), u16::from(b[1]), u16::from(b[2]));
            [b0 | (b1 & 0x0F) << 8, b1 >> 4 | b2 << 4]
        })
        .enumerate()
        .find(|&(_, c)| c >= q)
}

#[test]
fn v3_19_an_ek_failing_the_key_check_is_an_error() {
    let v = row(section_2(), "V3-19");
    let given = obj(v, "given");
    let expect = obj(v, "expect");
    let check = |key: &str| {
        acvp_case(
            "encapsulation_key_check",
            u64_field(given, &format!("acvp_encapsulationKeyCheck_tcId_{key}")),
        )
    };
    let (invalid, valid) = (check("invalid"), check("valid"));
    assert_eq!(invalid.get("testPassed"), Some(&Value::Bool(false)));
    assert_eq!(valid.get("testPassed"), Some(&Value::Bool(true)));
    assert_eq!(s(invalid, "reason"), s(given, "acvp_reason_invalid"));

    let head = &v3_09_meta_bytes()[..66];
    let bad_bytes = hx(given, "meta_address_invalid_ek");
    let good_bytes = hx(given, "meta_address_valid_ek");
    assert_eq!(bad_bytes, [head, &hx(invalid, "ek")].concat());
    assert_eq!(good_bytes, [head, &hx(valid, "ek")].concat());

    let first = obj(expect, "first_coefficient_at_least_q");
    let q = u16::try_from(u64_field(first, "q")).unwrap();
    assert_eq!(q, 3329);
    let (index, value) = first_coefficient_at_least_q(&bad_bytes[66..], q).expect("NIST: invalid");
    assert_eq!(u64::try_from(index).unwrap(), u64_field(first, "index"));
    assert_eq!(u64::from(value), u64_field(first, "value"));
    assert_eq!(first_coefficient_at_least_q(&good_bytes[66..], q), None);

    // §2.2 puts the check "before its first use". This decoder leaves it to encapsulation.
    let seed = [[0x22u8; 32], [0x44u8; 32]].concat();
    let bad = SchemeId3::meta_from_bytes(&bad_bytes).expect("both points are valid");
    assert!(matches!(SchemeId3::announce(&bad, &seed), Err(Error::Kem)));
    assert!(matches!(SchemeId3::announce_random(&bad), Err(Error::Kem)));
    let good = SchemeId3::meta_from_bytes(&good_bytes).expect("both points are valid");
    SchemeId3::announce(&good, &seed).expect("a valid ek encapsulates");

    // §2.8's generateStealthAddress.
    assert_eq!(
        erc5564::generate_stealth_address(&bad_bytes),
        Err(Error::Kem)
    );
    erc5564::generate_stealth_address(&good_bytes).expect("a valid ek encapsulates");
}
