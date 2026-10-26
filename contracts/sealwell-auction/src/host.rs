//! BLS12-381 operations routed through NEAR host functions (NEP-488) instead of
//! in-Wasm arkworks arithmetic. arkworks' uncompressed encoding is the zcash
//! big-endian format the host expects (verified on testnet by the CKD key check).
use ark_bls12_381::{Fq, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use near_sdk::env;
use sha2::{Digest, Sha256};

pub fn g1_unc(p: &G1Affine) -> Vec<u8> {
    let mut v = Vec::with_capacity(96);
    p.serialize_uncompressed(&mut v).unwrap();
    v
}
pub fn g2_unc(p: &G2Affine) -> Vec<u8> {
    let mut v = Vec::with_capacity(192);
    p.serialize_uncompressed(&mut v).unwrap();
    v
}
/// Host outputs are on-curve subgroup points, so skip arkworks' (expensive) checks.
pub fn g1_from_host(b: &[u8]) -> G1Affine {
    G1Affine::deserialize_uncompressed_unchecked(b).expect("host g1")
}
pub fn g2_from_host(b: &[u8]) -> G2Affine {
    G2Affine::deserialize_uncompressed_unchecked(b).expect("host g2")
}
fn scalar_le(s: &Fr) -> Vec<u8> {
    s.into_bigint().to_bytes_le()
}

/// Decompress (with subgroup check, done by the host) a 48-byte G1 point.
pub fn g1_decompress(b: &[u8]) -> G1Affine {
    g1_from_host(&env::bls12381_p1_decompress(b))
}
/// Decompress (with subgroup check, done by the host) a 96-byte G2 point.
pub fn g2_decompress(b: &[u8]) -> G2Affine {
    g2_from_host(&env::bls12381_p2_decompress(b))
}

/// Σ sᵢ·Pᵢ in G1.
pub fn g1_msm(terms: &[(G1Affine, Fr)]) -> G1Affine {
    let mut input = Vec::with_capacity(terms.len() * 128);
    for (p, s) in terms {
        input.extend(g1_unc(p));
        input.extend(scalar_le(s));
    }
    g1_from_host(&env::bls12381_g1_multiexp(&input))
}
/// Σ sᵢ·Pᵢ in G2.
pub fn g2_msm(terms: &[(G2Affine, Fr)]) -> G2Affine {
    let mut input = Vec::with_capacity(terms.len() * 224);
    for (p, s) in terms {
        input.extend(g2_unc(p));
        input.extend(scalar_le(s));
    }
    g2_from_host(&env::bls12381_g2_multiexp(&input))
}

/// RFC 9380 expand_message_xmd with SHA-256.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Vec<u8> {
    let ell = (len + 31) / 32;
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);
    let mut h = Sha256::new();
    h.update([0u8; 64]);
    h.update(msg);
    h.update((len as u16).to_be_bytes());
    h.update([0u8]);
    h.update(&dst_prime);
    let b0: [u8; 32] = h.finalize().into();
    let mut h = Sha256::new();
    h.update(b0);
    h.update([1u8]);
    h.update(&dst_prime);
    let mut bi: [u8; 32] = h.finalize().into();
    let mut out = bi.to_vec();
    for i in 2..=ell {
        let mut x = [0u8; 32];
        for j in 0..32 {
            x[j] = b0[j] ^ bi[j];
        }
        let mut h = Sha256::new();
        h.update(x);
        h.update([i as u8]);
        h.update(&dst_prime);
        bi = h.finalize().into();
        out.extend_from_slice(&bi);
    }
    out.truncate(len);
    out
}

/// hash_to_curve G1 (SSWU, RO) with field hashing in Wasm and the map + cofactor
/// clearing + addition on the host: H = map(u0) + map(u1).
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1Affine {
    let uniform = expand_message_xmd(msg, dst, 128);
    let mut fps = Vec::with_capacity(96);
    for chunk in uniform.chunks(64) {
        let u = Fq::from_be_bytes_mod_order(chunk);
        let mut be = u.into_bigint().to_bytes_be();
        while be.len() < 48 {
            be.insert(0, 0);
        }
        fps.extend(be);
    }
    let pts = env::bls12381_map_fp_to_g1(&fps);
    let mut sum_in = Vec::with_capacity(194);
    sum_in.push(0);
    sum_in.extend_from_slice(&pts[..96]);
    sum_in.push(0);
    sum_in.extend_from_slice(&pts[96..192]);
    g1_from_host(&env::bls12381_p1_sum(&sum_in))
}

/// Identity point H(mpk ‖ app_id) for NEAR CKD, via the host.
pub fn identity_point(mpk: &G2Affine, app_id: &[u8; 32]) -> G1Affine {
    let mut input = sealwell_ibe::g2_to_bytes(mpk).to_vec();
    input.extend_from_slice(app_id);
    hash_to_g1(&input, sealwell_ibe::NEAR_CKD_DST)
}
