//! # sealwell-ibe
//!
//! Boneh–Franklin identity-based encryption (with the Fujisaki–Okamoto transform)
//! keyed to identities whose private keys are produced by NEAR's MPC
//! *Confidential Key Derivation* (CKD) domain.
//!
//! * Identity: `app_id = SHA3-256("near-mpc v0.1.0 app_id derivation:" ‖ account ‖ "," ‖ path)`
//! * Hash: `H = hash_to_curve_G1(mpk_compressed_G2 ‖ app_id)`, RFC 9380,
//!   DST `NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_`
//! * Identity key (released by CKD): `sk_id = msk · H` in G1, checked by `e(sk_id, G2) = e(H, mpk)`.
//! * Ciphertext: `U = r·G2`, `V = σ ⊕ KDF(e(H, mpk)^r)`, `W = AEAD_{K(σ)}(M)` with `r = H3(σ, M)`.
//!
//! Unaudited research code. Testnet only.

#![forbid(unsafe_code)]

use ark_bls12_381::{g1, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

#[cfg(feature = "wasm")]
pub mod wasm;

/// Prefix used by near/mpc `derive_app_id`.
pub const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";
/// Hash-to-curve DST used by the NEAR MPC contract and threshold-signatures crate.
pub const NEAR_CKD_DST: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

const TAG_H2: &[u8] = b"sealwell-ibe/v1/H2-mask";
const TAG_H3: &[u8] = b"sealwell-ibe/v1/H3-r";
const TAG_H4: &[u8] = b"sealwell-ibe/v1/H4-aead-key";
pub const SIGMA_LEN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid encoding: {0}")]
    Encoding(&'static str),
    #[error("released key does not verify against mpk and identity")]
    BadKey,
    #[error("decryption failed")]
    Decrypt,
    #[error("ciphertext fails FO consistency check")]
    NotWellFormed,
}

pub type Result<T> = core::result::Result<T, Error>;

/// 32-byte CKD application id.
pub type AppId = [u8; 32];

/// `app_id = SHA3-256(prefix ‖ account ‖ "," ‖ path)` (matches near/mpc `kdf::derive_app_id`).
pub fn derive_app_id(account_id: &str, derivation_path: &str) -> AppId {
    let mut h = Sha3_256::new();
    h.update(APP_ID_DERIVATION_PREFIX.as_bytes());
    h.update(account_id.as_bytes());
    h.update(b",");
    h.update(derivation_path.as_bytes());
    h.finalize().into()
}

/// Compressed (ZCash format, 96 bytes) encoding of a G2 point.
pub fn g2_to_bytes(p: &G2Affine) -> [u8; 96] {
    let mut out = [0u8; 96];
    p.serialize_compressed(&mut out[..]).expect("fixed size");
    out
}
/// Compressed (ZCash format, 48 bytes) encoding of a G1 point.
pub fn g1_to_bytes(p: &G1Affine) -> [u8; 48] {
    let mut out = [0u8; 48];
    p.serialize_compressed(&mut out[..]).expect("fixed size");
    out
}
pub fn g1_from_bytes(b: &[u8]) -> Result<G1Affine> {
    G1Affine::deserialize_compressed(b).map_err(|_| Error::Encoding("G1 point"))
}
pub fn g2_from_bytes(b: &[u8]) -> Result<G2Affine> {
    G2Affine::deserialize_compressed(b).map_err(|_| Error::Encoding("G2 point"))
}

fn strip_b58<'a>(s: &'a str, prefix: &str) -> Result<Vec<u8>> {
    let body = s.strip_prefix(prefix).ok_or(Error::Encoding("missing curve prefix"))?;
    bs58::decode(body).into_vec().map_err(|_| Error::Encoding("base58"))
}
/// Parse a NEAR `bls12381g1:<base58>` string.
pub fn parse_near_g1(s: &str) -> Result<G1Affine> {
    g1_from_bytes(&strip_b58(s, "bls12381g1:")?)
}
/// Parse a NEAR `bls12381g2:<base58>` string.
pub fn parse_near_g2(s: &str) -> Result<G2Affine> {
    g2_from_bytes(&strip_b58(s, "bls12381g2:")?)
}
pub fn format_near_g1(p: &G1Affine) -> String {
    format!("bls12381g1:{}", bs58::encode(g1_to_bytes(p)).into_string())
}
pub fn format_near_g2(p: &G2Affine) -> String {
    format!("bls12381g2:{}", bs58::encode(g2_to_bytes(p)).into_string())
}

/// RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` with the NEAR CKD DST.
pub fn hash_to_g1(msg: &[u8]) -> G1Affine {
    let hasher = MapToCurveBasedHasher::<
        G1Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<g1::Config>,
    >::new(NEAR_CKD_DST)
    .expect("valid DST");
    hasher.hash(msg).expect("hash_to_curve")
}

/// `H(mpk, app_id) = hash_to_g1(compress(mpk) ‖ app_id)` — the CKD identity point.
pub fn identity_point(mpk: &G2Affine, app_id: &AppId) -> G1Affine {
    let mut input = Vec::with_capacity(96 + 32);
    input.extend_from_slice(&g2_to_bytes(mpk));
    input.extend_from_slice(app_id);
    hash_to_g1(&input)
}

/// Check a released identity key: `e(key, G2) == e(H(mpk, app_id), mpk)`.
pub fn verify_key(mpk: &G2Affine, app_id: &AppId, key: &G1Affine) -> bool {
    if key.is_zero() {
        return false;
    }
    let h = identity_point(mpk, app_id);
    Bls12_381::pairing(*key, G2Affine::generator()) == Bls12_381::pairing(h, *mpk)
}

/// Unwrap CKD output `(big_y, big_c)` with app scalar `a`: `key = C − a·Y`.
pub fn ckd_unwrap(a: &Fr, big_y: &G1Affine, big_c: &G1Affine) -> G1Affine {
    (G1Projective::from(*big_c) - *big_y * a).into_affine()
}

/// Parse a 32-byte big-endian scalar (as printed by JS / noble), reduced mod r.
pub fn scalar_from_be_hex(h: &str) -> Result<Fr> {
    let b = hex::decode(h).map_err(|_| Error::Encoding("hex"))?;
    Ok(Fr::from_be_bytes_mod_order(&b))
}

/// The public (pk1 = a·G1, pk2 = a·G2) pair for an `AppPublicKeyPV` request.
pub fn app_public_key_pv(a: &Fr) -> (G1Affine, G2Affine) {
    (
        (G1Affine::generator() * a).into_affine(),
        (G2Affine::generator() * a).into_affine(),
    )
}

/// Boneh–Franklin FullIdent ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// `U = r·G2`
    pub u: G2Affine,
    /// `V = σ ⊕ H2(g^r)`
    pub v: [u8; SIGMA_LEN],
    /// `W = ChaCha20-Poly1305_{H4(σ)}(M)`, AAD binds `U ‖ V ‖ app_id`.
    pub w: Vec<u8>,
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + SIGMA_LEN + self.w.len());
        out.extend_from_slice(&g2_to_bytes(&self.u));
        out.extend_from_slice(&self.v);
        out.extend_from_slice(&self.w);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 96 + SIGMA_LEN + 16 {
            return Err(Error::Encoding("ciphertext too short"));
        }
        let u = g2_from_bytes(&b[..96])?;
        let mut v = [0u8; SIGMA_LEN];
        v.copy_from_slice(&b[96..96 + SIGMA_LEN]);
        Ok(Self { u, v, w: b[96 + SIGMA_LEN..].to_vec() })
    }
}

fn gt_bytes(g: &<Bls12_381 as Pairing>::TargetField) -> Vec<u8> {
    let mut out = Vec::new();
    g.serialize_compressed(&mut out).expect("serialize Gt");
    out
}
fn h2(gt: &[u8], u: &G2Affine) -> [u8; SIGMA_LEN] {
    let mut h = Sha256::new();
    h.update(TAG_H2);
    h.update(g2_to_bytes(u));
    h.update(gt);
    h.finalize().into()
}
fn h3(sigma: &[u8; SIGMA_LEN], msg: &[u8], app_id: &AppId) -> Fr {
    let mut wide = [0u8; 64];
    for (i, chunk) in wide.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(TAG_H3);
        h.update([i as u8]);
        h.update(app_id);
        h.update(sigma);
        h.update((msg.len() as u64).to_le_bytes());
        h.update(msg);
        chunk.copy_from_slice(&h.finalize());
    }
    Fr::from_le_bytes_mod_order(&wide)
}
fn h4(sigma: &[u8; SIGMA_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TAG_H4);
    h.update(sigma);
    h.finalize().into()
}
fn aad(u: &G2Affine, v: &[u8; SIGMA_LEN], app_id: &AppId) -> Vec<u8> {
    let mut a = g2_to_bytes(u).to_vec();
    a.extend_from_slice(v);
    a.extend_from_slice(app_id);
    a
}

/// Fixed plaintext length for sealed orders, so every ciphertext has the same size
/// (96 + 32 + ORDER_PT_LEN + 16 = 208 bytes).
pub const ORDER_PT_LEN: usize = 64;
/// Ciphertext length of a padded order.
pub const ORDER_CT_LEN: usize = 96 + SIGMA_LEN + ORDER_PT_LEN + 16;

/// Right-pad an order (JSON) with spaces to `ORDER_PT_LEN`. JSON parsers ignore trailing
/// whitespace, so the padded plaintext still parses. Returns `None` if the order is too long.
pub fn pad_order(order: &[u8]) -> Option<Vec<u8>> {
    if order.len() > ORDER_PT_LEN || order.ends_with(b" ") {
        return None;
    }
    let mut v = order.to_vec();
    v.resize(ORDER_PT_LEN, b' ');
    Some(v)
}

/// Seal an order: pad to the fixed length, then encrypt.
pub fn encrypt_order<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &G2Affine,
    app_id: &AppId,
    order: &[u8],
) -> Option<(Ciphertext, [u8; SIGMA_LEN])> {
    Some(encrypt(rng, mpk, app_id, &pad_order(order)?))
}

/// Deterministic encryption given σ (exposed for verification and tests).
pub fn encrypt_with_sigma(
    mpk: &G2Affine,
    app_id: &AppId,
    msg: &[u8],
    sigma: &[u8; SIGMA_LEN],
) -> Ciphertext {
    let r = h3(sigma, msg, app_id);
    let u = (G2Affine::generator() * r).into_affine();
    let h = identity_point(mpk, app_id);
    let g = Bls12_381::pairing(h, (G2Projective::from(*mpk) * r).into_affine());
    let mask = h2(&gt_bytes(&g.0), &u);
    let mut v = [0u8; SIGMA_LEN];
    for i in 0..SIGMA_LEN {
        v[i] = sigma[i] ^ mask[i];
    }
    let cipher = ChaCha20Poly1305::new((&h4(sigma)).into());
    let w = cipher
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg, aad: &aad(&u, &v, app_id) })
        .expect("aead encrypt");
    Ciphertext { u, v, w }
}

/// Encrypt `msg` to identity `app_id` under the MPC CKD master public key `mpk`.
pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    mpk: &G2Affine,
    app_id: &AppId,
    msg: &[u8],
) -> (Ciphertext, [u8; SIGMA_LEN]) {
    let mut sigma = [0u8; SIGMA_LEN];
    rng.fill_bytes(&mut sigma);
    (encrypt_with_sigma(mpk, app_id, msg, &sigma), sigma)
}

/// Decrypt with the released identity key. Performs the FO re-encryption check,
/// so a malformed ciphertext is rejected (CCA security in the ROM).
/// Returns `(plaintext, sigma)`; `sigma` is a publicly checkable opening.
pub fn decrypt(
    mpk: &G2Affine,
    app_id: &AppId,
    key: &G1Affine,
    ct: &Ciphertext,
) -> Result<(Vec<u8>, [u8; SIGMA_LEN])> {
    let _ = mpk; // kept for API symmetry; identity binding is via app_id in H3 / AAD
    let g = Bls12_381::pairing(*key, ct.u);
    let mask = h2(&gt_bytes(&g.0), &ct.u);
    let mut sigma = [0u8; SIGMA_LEN];
    for i in 0..SIGMA_LEN {
        sigma[i] = ct.v[i] ^ mask[i];
    }
    let cipher = ChaCha20Poly1305::new((&h4(&sigma)).into());
    let msg = cipher
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: &ct.w, aad: &aad(&ct.u, &ct.v, app_id) })
        .map_err(|_| Error::Decrypt)?;
    let r = h3(&sigma, &msg, app_id);
    if (G2Affine::generator() * r).into_affine() != ct.u {
        return Err(Error::NotWellFormed);
    }
    Ok((msg, sigma))
}

/// Verify the released key first, then decrypt.
pub fn decrypt_checked(
    mpk: &G2Affine,
    app_id: &AppId,
    key: &G1Affine,
    ct: &Ciphertext,
) -> Result<Vec<u8>> {
    if !verify_key(mpk, app_id, key) {
        return Err(Error::BadKey);
    }
    decrypt(mpk, app_id, key, ct).map(|(m, _)| m)
}

/// Deterministically check that `(msg, sigma)` is the unique opening of `ct`
/// — no identity key needed. This lets anyone (e.g. a contract) verify a claimed
/// plaintext published by a keeper.
pub fn verify_opening(
    mpk: &G2Affine,
    app_id: &AppId,
    ct: &Ciphertext,
    msg: &[u8],
    sigma: &[u8; SIGMA_LEN],
) -> bool {
    &encrypt_with_sigma(mpk, app_id, msg, sigma) == ct
}

/// The FO scalar `r = H3(σ, M, app_id)`; a valid ciphertext has `U = r·G2`.
/// Exposed so an on-chain verifier can check `U` with a host multiexp.
pub fn opening_scalar(app_id: &AppId, msg: &[u8], sigma: &[u8; SIGMA_LEN]) -> Fr {
    h3(sigma, msg, app_id)
}

/// Opening check that uses the *released* identity key instead of re-encrypting:
/// recomputes `σ' = V ⊕ H2(e(key, U))`, requires `σ' == σ`, and requires the AEAD
/// to open to `msg`. Together with the caller checking `U == opening_scalar(..)·G2`
/// (and `key` being verified against `mpk`), this is exactly the FO check performed
/// by [`decrypt`], so a ciphertext the keeper cannot decrypt can't be "opened" either.
/// Costs one pairing and no hash-to-curve / G2 scalar multiplication.
pub fn verify_opening_with_key(
    app_id: &AppId,
    key: &G1Affine,
    u: &G2Affine,
    v: &[u8; SIGMA_LEN],
    w: &[u8],
    msg: &[u8],
    sigma: &[u8; SIGMA_LEN],
) -> bool {
    let g = Bls12_381::pairing(*key, *u);
    let mask = h2(&gt_bytes(&g.0), u);
    for i in 0..SIGMA_LEN {
        if v[i] ^ mask[i] != sigma[i] {
            return false;
        }
    }
    let cipher = ChaCha20Poly1305::new((&h4(sigma)).into());
    match cipher.decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: w, aad: &aad(u, v, app_id) }) {
        Ok(m) => m == msg,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn padded_orders_have_constant_ciphertext_length() {
        use ark_ff::UniformRand;
        let mut rng = rand::rngs::OsRng;
        let mpk = (G2Affine::generator() * Fr::rand(&mut rng)).into_affine();
        let id = derive_app_id("a.testnet", "sealwell/batch/0");
        let short = br#"{"side":"buy","price":"1","qty":"1"}"#;
        let long = br#"{"side":"sell","price":"340282366920938","qty":"99999999999"}"#;
        let (a, _) = encrypt_order(&mut rng, &mpk, &id, short).unwrap();
        let (b, _) = encrypt_order(&mut rng, &mpk, &id, long).unwrap();
        assert_eq!(a.to_bytes().len(), ORDER_CT_LEN);
        assert_eq!(b.to_bytes().len(), ORDER_CT_LEN);
        assert!(pad_order(&[b'x'; ORDER_PT_LEN + 1]).is_none());
        assert!(pad_order(b"{} ").is_none());
        assert_eq!(std::str::from_utf8(&pad_order(short).unwrap()).unwrap().trim_end().as_bytes(), short);
    }

    #[test]
    fn opening_with_key_matches_fo() {
        let mut rng = StdRng::seed_from_u64(77);
        let msk = Fr::rand(&mut rng);
        let mpk = (G2Affine::generator() * msk).into_affine();
        let app_id = derive_app_id("x.testnet", "sealwell/batch/3");
        let key = (identity_point(&mpk, &app_id) * msk).into_affine();
        let (ct, sigma) = encrypt(&mut rng, &mpk, &app_id, b"order");
        assert_eq!((G2Affine::generator() * opening_scalar(&app_id, b"order", &sigma)).into_affine(), ct.u);
        assert!(verify_opening_with_key(&app_id, &key, &ct.u, &ct.v, &ct.w, b"order", &sigma));
        assert!(!verify_opening_with_key(&app_id, &key, &ct.u, &ct.v, &ct.w, b"other", &sigma));
        let mut bad_v = ct.v; bad_v[0] ^= 1;
        assert!(!verify_opening_with_key(&app_id, &key, &ct.u, &bad_v, &ct.w, b"order", &sigma));
    }

    use super::*;
    use ark_ff::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};

    fn setup() -> (Fr, G2Affine, AppId, G1Affine) {
        let mut rng = StdRng::seed_from_u64(7);
        let msk = Fr::rand(&mut rng);
        let mpk = (G2Affine::generator() * msk).into_affine();
        let app_id = derive_app_id("auction.sealwell.testnet", "batch/1");
        let key = (identity_point(&mpk, &app_id) * msk).into_affine();
        (msk, mpk, app_id, key)
    }

    #[test]
    fn app_id_is_deterministic_and_path_sensitive() {
        assert_eq!(derive_app_id("a.near", "x"), derive_app_id("a.near", "x"));
        assert_ne!(derive_app_id("a.near", "x"), derive_app_id("a.near", "y"));
        assert_ne!(derive_app_id("a.near", "x"), derive_app_id("b.near", "x"));
    }

    #[test]
    fn key_verifies_and_wrong_key_fails() {
        let (_, mpk, app_id, key) = setup();
        assert!(verify_key(&mpk, &app_id, &key));
        let other = derive_app_id("auction.sealwell.testnet", "batch/2");
        assert!(!verify_key(&mpk, &other, &key));
        assert!(!verify_key(&mpk, &app_id, &G1Affine::zero()));
    }

    #[test]
    fn roundtrip_and_opening() {
        let (_, mpk, app_id, key) = setup();
        let mut rng = StdRng::seed_from_u64(1);
        let (ct, sigma) = encrypt(&mut rng, &mpk, &app_id, b"bid: 100 USDC @ 3.21");
        let ct2 = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
        let (m, s) = decrypt(&mpk, &app_id, &key, &ct2).unwrap();
        assert_eq!(m, b"bid: 100 USDC @ 3.21");
        assert_eq!(s, sigma);
        assert!(verify_opening(&mpk, &app_id, &ct, &m, &s));
        assert!(!verify_opening(&mpk, &app_id, &ct, b"bid: 999", &s));
    }

    #[test]
    fn wrong_identity_key_cannot_decrypt() {
        let (msk, mpk, app_id, _) = setup();
        let other = derive_app_id("auction.sealwell.testnet", "batch/2");
        let other_key = (identity_point(&mpk, &other) * msk).into_affine();
        let mut rng = StdRng::seed_from_u64(2);
        let (ct, _) = encrypt(&mut rng, &mpk, &app_id, b"secret");
        assert!(decrypt(&mpk, &app_id, &other_key, &ct).is_err());
        assert_eq!(decrypt_checked(&mpk, &app_id, &other_key, &ct), Err(Error::BadKey));
    }

    #[test]
    fn tampering_is_rejected() {
        let (_, mpk, app_id, key) = setup();
        let mut rng = StdRng::seed_from_u64(3);
        let (ct, _) = encrypt(&mut rng, &mpk, &app_id, b"secret");
        let mut bad = ct.clone();
        bad.w[0] ^= 1;
        assert!(decrypt(&mpk, &app_id, &key, &bad).is_err());
        let mut bad = ct.clone();
        bad.v[0] ^= 1;
        assert!(decrypt(&mpk, &app_id, &key, &bad).is_err());
        // Swap U for an unrelated point: FO check / AEAD must fail.
        let mut bad = ct;
        bad.u = (G2Affine::generator() * Fr::from(5u64)).into_affine();
        assert!(decrypt(&mpk, &app_id, &key, &bad).is_err());
    }

    #[test]
    fn ckd_unwrap_roundtrip() {
        let (msk, mpk, app_id, key) = setup();
        let mut rng = StdRng::seed_from_u64(4);
        let a = Fr::rand(&mut rng);
        let y_s = Fr::rand(&mut rng);
        let (pk1, _) = app_public_key_pv(&a);
        // MPC side: Y = y·G1, C = msk·H + y·A
        let big_y = (G1Affine::generator() * y_s).into_affine();
        let big_c = ((identity_point(&mpk, &app_id) * msk) + pk1 * y_s).into_affine();
        assert_eq!(ckd_unwrap(&a, &big_y, &big_c), key);
    }

    #[test]
    fn near_string_encoding_roundtrip() {
        let (_, mpk, _, key) = setup();
        assert_eq!(parse_near_g2(&format_near_g2(&mpk)).unwrap(), mpk);
        assert_eq!(parse_near_g1(&format_near_g1(&key)).unwrap(), key);
        assert!(parse_near_g1("ed25519:abc").is_err());
    }
}
