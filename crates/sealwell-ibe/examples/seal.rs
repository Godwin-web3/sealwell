//! Bidder-side helper: `seal <contract> <batch_id> <order_json>` prints `ct_hex sigma_hex` (order padded to a fixed length).
//! `seal --open <contract> <batch_id> <key_hex_compressed_g1> <ct_hex>` decrypts with a released batch key.
use sealwell_ibe::*;
const MPK: &str = "bls12381g2:xeYho48G2Sr9oJz4gw9sLGZGspeeKpHZvMDAwWvoNTRnVMFJH96GxX98TT2MRhTtsot1wcGR1Ti2Xh8PCsbYJ2enbLNdJXDvTYSK8aTE3nJ5NZXU7Kt1F6mFtReWs5pR4kj";
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mpk = parse_near_g2(&std::env::var("SEALWELL_MPK").unwrap_or(MPK.into())).unwrap();
    if a[0] == "--open" {
        let app_id = derive_app_id(&a[1], &format!("sealwell/batch/{}", a[2]));
        let key = g1_from_bytes(&hex::decode(&a[3]).unwrap()).unwrap();
        let ct = Ciphertext::from_bytes(&hex::decode(&a[4]).unwrap()).unwrap();
        let m = decrypt_checked(&mpk, &app_id, &key, &ct).expect("decrypt");
        println!("{}", String::from_utf8(m).unwrap().trim_end());
    } else {
        let app_id = derive_app_id(&a[0], &format!("sealwell/batch/{}", a[1]));
        let (ct, sigma) = encrypt_order(&mut rand::rngs::OsRng, &mpk, &app_id, a[2].as_bytes()).expect("order longer than ORDER_PT_LEN");
        println!("{} {}", hex::encode(ct.to_bytes()), hex::encode(sigma));
    }
}
