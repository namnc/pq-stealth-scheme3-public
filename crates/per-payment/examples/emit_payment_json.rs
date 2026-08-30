//! Deterministic fixture generator for the end-to-end payment gas benchmark.
use pqsa_core::{ExportableSpendKey, SenderState, StealthScheme};
use pqsa_per_payment::SchemeId3;
use serde_json::{Value, json};

fn prefixed_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn fixture<S: StealthScheme + ExportableSpendKey>(
    name: &str,
    scheme_id: u32,
    keygen_len: usize,
) -> Value {
    let seed: Vec<u8> = (0..keygen_len as u32)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
        .collect();
    let (meta, master, tracking) = S::keygen(&seed).expect("fixture key generation");
    let mut sender = SenderState::resume([0x5a; 32], 0);
    let announcement_seed = sender.draw_seed::<S>().expect("fixture announcement seed");
    let announcement = S::announce(&meta, &announcement_seed).expect("fixture announcement");
    let (address, epk_field, metadata) = S::announcement_to_bytes(&announcement);
    let scanner = S::bind(&tracking, &meta).expect("fixture scanner binding");
    let matched = S::scan(&scanner, &announcement).expect("fixture must scan");
    let spend_key = S::spend_key(&master, &matched).expect("fixture spend key");
    json!({
        "name": name,
        "scheme_id": scheme_id,
        "meta_address": prefixed_hex(&S::meta_to_bytes(&meta)),
        "stealth_address": prefixed_hex(&address),
        "spend_key": prefixed_hex(S::spend_key_bytes(&spend_key)),
        "epk_field": prefixed_hex(&epk_field),
        "metadata": prefixed_hex(&metadata),
    })
}

fn main() {
    println!("{}", fixture::<SchemeId3>("scheme3-demo-v1", 3, 128));
}
