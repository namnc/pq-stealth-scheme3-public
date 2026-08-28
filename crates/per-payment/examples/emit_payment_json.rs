//! Local operator tool: the fifteen lines `harness/payment/README.md` says a
//! library-only tree writes for itself. NOT part of the release; deleted after use.
use pqsa_core::{ExportableSpendKey, SenderState, StealthScheme};
use pqsa_per_payment::SchemeId3;

fn hex(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

fn case<S: StealthScheme + ExportableSpendKey>(scheme_id: u32, keygen_len: usize) -> String {
    let seed: Vec<u8> = (0..keygen_len as u32)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
        .collect();
    let (meta, master, tracking) = S::keygen(&seed).unwrap();
    let mut sender = SenderState::resume([0x5a; 32], 0);
    let ann = S::announce(&meta, &sender.draw_seed::<S>().unwrap()).unwrap();
    let (addr, epk_field, metadata) = S::announcement_to_bytes(&ann);
    let scanner = S::bind(&tracking, &meta).unwrap();
    let m = S::scan(&scanner, &ann).expect("our own payment");
    let sk = S::spend_key(&master, &m).unwrap();
    format!(
        r#"{{"scheme_id": {scheme_id}, "stealth_address": "{}", "spend_key": "{}", "epk_field": "{}", "metadata": "{}"}}"#,
        hex(&addr),
        hex(S::spend_key_bytes(&sk)),
        hex(&epk_field),
        hex(&metadata)
    )
}

fn main() {
    println!(r#"{{"cases": [{}]}}"#, case::<SchemeId3>(3, 128));
}
