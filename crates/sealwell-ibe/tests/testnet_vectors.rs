//! Real public values from NEAR testnet `v1.signer-prod.testnet`, domain 2 (CKD).
//! Caller: sealwell-probe-1793003413.testnet, derivation_path "sealwell-batch-0".
//! The app scalar `a` is public by design (AppPublicKeyPV with a published scalar
//! means the derived key is public — exactly what a batch reveal wants).
use sealwell_ibe::*;

const MPK: &str = "bls12381g2:xeYho48G2Sr9oJz4gw9sLGZGspeeKpHZvMDAwWvoNTRnVMFJH96GxX98TT2MRhTtsot1wcGR1Ti2Xh8PCsbYJ2enbLNdJXDvTYSK8aTE3nJ5NZXU7Kt1F6mFtReWs5pR4kj";
const ACCOUNT: &str = "sealwell-probe-1793003413.testnet";
const PATH: &str = "sealwell-batch-0";
const APP_ID_HEX: &str = "cfd92a270feb4be4ef09945120f63527b031d0b6ffffbf68369139b98ba76537";
/// Key decrypted & pairing-verified by the JS probe (tx C1WHYDd99EhBrBQLujiKqyY5SSnDhrzaigNJduLXwoRP).
const PROBE_KEY_HEX: &str = "992f0ff1acf183a9121b2bbe6bbfbae8cfe79b64b3bc401dc0b0946208d1269e4370883f09219101e5f0e85706375823";
/// Second call, tx HM49W4zbwtDzWUvyogidh86NMLhZQW2gAPLdd7eCXPx7, with the scalar recorded.
const A_HEX: &str = "24fa2292a2a417bd222abde0877cfd6125ac1c958089dd43c01c180f25e072a6";
const BIG_Y: &str = "bls12381g1:7UJ7mxhhguAkSKbqaXcWZ2S6yoNqSrqfVETVF77ej6i1iVCcWTi8TDKBNzvHrcz5BP";
const BIG_C: &str = "bls12381g1:6P6nENcDxcCTTeX7CGHYVfV2A8AKpr3Eet7gi7viZ7p6otPYDqvkdZoKqkFH9XrAtE";

#[test]
fn app_id_matches_near_mpc() {
    assert_eq!(hex::encode(derive_app_id(ACCOUNT, PATH)), APP_ID_HEX);
}

#[test]
fn probe_key_verifies_against_testnet_mpk() {
    let mpk = parse_near_g2(MPK).unwrap();
    let key = g1_from_bytes(&hex::decode(PROBE_KEY_HEX).unwrap()).unwrap();
    assert!(verify_key(&mpk, &derive_app_id(ACCOUNT, PATH), &key));
    assert!(!verify_key(&mpk, &derive_app_id(ACCOUNT, "other"), &key));
}

#[test]
fn unwrap_testnet_ckd_output_reproduces_probe_key() {
    let mpk = parse_near_g2(MPK).unwrap();
    let a = scalar_from_be_hex(A_HEX).unwrap();
    let key = ckd_unwrap(&a, &parse_near_g1(BIG_Y).unwrap(), &parse_near_g1(BIG_C).unwrap());
    assert_eq!(hex::encode(g1_to_bytes(&key)), PROBE_KEY_HEX);
    assert!(verify_key(&mpk, &derive_app_id(ACCOUNT, PATH), &key));
}

#[test]
fn end_to_end_encrypt_to_identity_then_decrypt_with_released_key() {
    let mpk = parse_near_g2(MPK).unwrap();
    let app_id = derive_app_id(ACCOUNT, PATH);
    // Bidder: knows only public mpk + identity, before any key exists.
    let (ct, _) = encrypt(&mut rand_core::OsRng, &mpk, &app_id, b"sell 10 NEAR @ min 2.50 USDC");
    // Release: MPC CKD output unwrapped with the public scalar.
    let a = scalar_from_be_hex(A_HEX).unwrap();
    let key = ckd_unwrap(&a, &parse_near_g1(BIG_Y).unwrap(), &parse_near_g1(BIG_C).unwrap());
    let ct = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
    assert_eq!(decrypt_checked(&mpk, &app_id, &key, &ct).unwrap(), b"sell 10 NEAR @ min 2.50 USDC");
    // Another batch identity's ciphertext stays sealed under this key.
    let other = derive_app_id(ACCOUNT, "sealwell-batch-1");
    let (ct2, _) = encrypt(&mut rand_core::OsRng, &mpk, &other, b"x");
    assert!(decrypt(&mpk, &other, &key, &ct2).is_err());
}
