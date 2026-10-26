//! Minimal wasm-bindgen surface (feature `wasm`). Strings use NEAR `bls12381g{1,2}:` base58.
use wasm_bindgen::prelude::*;

fn e<E: core::fmt::Display>(x: E) -> JsError { JsError::new(&x.to_string()) }

#[wasm_bindgen]
pub fn derive_app_id_hex(account_id: &str, path: &str) -> String {
    hex::encode(crate::derive_app_id(account_id, path))
}

fn app_id(h: &str) -> Result<crate::AppId, JsError> {
    hex::decode(h).map_err(e)?.try_into().map_err(|_| JsError::new("app_id must be 32 bytes"))
}

/// Encrypt to an identity. Returns ciphertext bytes.
#[wasm_bindgen]
pub fn encrypt(mpk: &str, app_id_hex: &str, msg: &[u8]) -> Result<Vec<u8>, JsError> {
    let mpk = crate::parse_near_g2(mpk).map_err(e)?;
    let (ct, _) = crate::encrypt(&mut rand_core::OsRng, &mpk, &app_id(app_id_hex)?, msg);
    Ok(ct.to_bytes())
}

/// Decrypt with a released key (verified first).
#[wasm_bindgen]
pub fn decrypt(mpk: &str, app_id_hex: &str, key: &str, ct: &[u8]) -> Result<Vec<u8>, JsError> {
    let mpk = crate::parse_near_g2(mpk).map_err(e)?;
    let key = crate::parse_near_g1(key).map_err(e)?;
    let ct = crate::Ciphertext::from_bytes(ct).map_err(e)?;
    crate::decrypt_checked(&mpk, &app_id(app_id_hex)?, &key, &ct).map_err(e)
}

#[wasm_bindgen]
pub fn verify_key(mpk: &str, app_id_hex: &str, key: &str) -> Result<bool, JsError> {
    let mpk = crate::parse_near_g2(mpk).map_err(e)?;
    let key = crate::parse_near_g1(key).map_err(e)?;
    Ok(crate::verify_key(&mpk, &app_id(app_id_hex)?, &key))
}
