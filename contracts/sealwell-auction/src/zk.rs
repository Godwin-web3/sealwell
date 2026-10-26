//! Shielded deposit pool primitives: Poseidon (circomlib-compatible) incremental Merkle tree and
//! Groth16 (BN254) verification with NEAR's alt_bn128 host functions.
use crate::vk;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use crate::poseidon_consts;
use near_sdk::{env, near};
use sha2::{Digest, Sha256};

pub const LEVELS: usize = 16;
pub const ROOT_HISTORY: usize = 30;

pub fn fr_to_le(x: &Fr) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&x.into_bigint().to_bytes_le());
    o
}
/// Parse a canonical (< r) little-endian field element.
pub fn fr_from_le(b: &[u8; 32]) -> Option<Fr> {
    let x = Fr::from_le_bytes_mod_order(b);
    (fr_to_le(&x) == *b).then_some(x)
}
pub fn parse_hex32(h: &str) -> [u8; 32] {
    hex::decode(h).ok().and_then(|v| v.try_into().ok()).expect("expected 32-byte hex")
}

/// circomlib-compatible Poseidon for exactly 2 inputs (t=3, 8 full + 57 partial rounds).
pub struct Hasher { c: Vec<Fr>, m: [[Fr; 3]; 3] }
impl Hasher {
    pub fn new() -> Self {
        let f = |h: &str| Fr::from_le_bytes_mod_order(&parse_hex32(h));
        let c = poseidon_consts::C.iter().map(|h| f(h)).collect();
        let mut m = [[Fr::from(0u64); 3]; 3];
        for i in 0..9 { m[i / 3][i % 3] = f(poseidon_consts::M[i]); }
        Hasher { c, m }
    }
    pub fn hash2(&self, a: Fr, b: Fr) -> Fr {
        let pow5 = |x: Fr| { let x2 = x * x; x2 * x2 * x };
        let mut s = [Fr::from(0u64), a, b];
        for r in 0..65 {
            for i in 0..3 { s[i] += self.c[r * 3 + i]; }
            if r < 4 || r >= 61 { for i in 0..3 { s[i] = pow5(s[i]); } } else { s[0] = pow5(s[0]); }
            let mut n = [Fr::from(0u64); 3];
            for i in 0..3 { for j in 0..3 { n[i] += self.m[i][j] * s[j]; } }
            s = n;
        }
        s[0]
    }
}
pub fn poseidon(xs: &[Fr]) -> Fr {
    assert!(xs.len() == 2, "poseidon: 2 inputs only");
    Hasher::new().hash2(xs[0], xs[1])
}

#[near(serializers = [borsh])]
pub struct Tree {
    pub next_index: u32,
    pub zeros: Vec<[u8; 32]>,
    pub filled: Vec<[u8; 32]>,
    pub roots: Vec<[u8; 32]>,
    pub root_index: u32,
}

impl Tree {
    pub fn new() -> Self {
        let h = Hasher::new();
        let mut z = vec![Fr::from(0u64)];
        for i in 0..LEVELS {
            let n = h.hash2(z[i], z[i]);
            z.push(n);
        }
        let zeros: Vec<[u8; 32]> = z.iter().map(fr_to_le).collect();
        Tree { next_index: 0, filled: zeros[..LEVELS].to_vec(), roots: vec![zeros[LEVELS]], root_index: 0, zeros }
    }
    pub fn root(&self) -> [u8; 32] {
        self.roots[self.root_index as usize]
    }
    pub fn is_known_root(&self, r: &[u8; 32]) -> bool {
        self.roots.iter().any(|x| x == r)
    }
    /// Tornado-style insertion: LEVELS Poseidon hashes.
    pub fn insert(&mut self, leaf: Fr) -> u32 {
        let h = Hasher::new();
        let idx = self.next_index;
        require_lt(idx as u64, 1u64 << LEVELS);
        let mut cur = leaf;
        let mut i = idx;
        for l in 0..LEVELS {
            let (left, right) = if i & 1 == 0 {
                self.filled[l] = fr_to_le(&cur);
                (cur, fr_from_le(&self.zeros[l]).unwrap())
            } else {
                (fr_from_le(&self.filled[l]).unwrap(), cur)
            };
            cur = h.hash2(left, right);
            i >>= 1;
        }
        let r = fr_to_le(&cur);
        if self.roots.len() < ROOT_HISTORY {
            self.roots.push(r);
            self.root_index = (self.roots.len() - 1) as u32;
        } else {
            self.root_index = (self.root_index + 1) % ROOT_HISTORY as u32;
            self.roots[self.root_index as usize] = r;
        }
        self.next_index = idx + 1;
        idx
    }
}
fn require_lt(a: u64, b: u64) {
    near_sdk::require!(a < b, "tree full");
}

/// Binds a proof to its action; must match `extHash` in circuits/lib.mjs.
pub fn ext_hash(action: &str, batch_id: u64, ct: &[u8], payout: &str, relayer: &str, fee: u128) -> [u8; 32] {
    let ct_h = if ct.is_empty() { String::new() } else { hex::encode(Sha256::digest(ct)) };
    let s = near_sdk::serde_json::to_string(&[action.to_string(), batch_id.to_string(), ct_h, payout.to_string(), relayer.to_string(), fee.to_string()]).unwrap();
    let mut d: [u8; 32] = Sha256::digest(s.as_bytes()).into();
    d[0] &= 0x1f;
    d.reverse(); // big-endian integer -> little-endian field encoding
    d
}

/// Groth16 verification: e(-A,B)·e(α,β)·e(vk_x,γ)·e(C,δ) == 1, vk_x = IC0 + Σ sᵢ·ICᵢ.
/// `proof` = A (64) ‖ B (128) ‖ C (64) in NEAR alt_bn128 encoding; `inputs` are canonical LE scalars.
pub fn groth16_verify(proof: &[u8], inputs: &[[u8; 32]]) -> bool {
    if proof.len() != 256 || inputs.len() != vk::N_PUBLIC {
        return false;
    }
    let (a, rest) = proof.split_at(64);
    let (b, c) = rest.split_at(128);
    let mut me = Vec::with_capacity(96 * (inputs.len() + 1));
    let one = { let mut o = [0u8; 32]; o[0] = 1; o };
    me.extend(hex::decode(vk::IC[0]).unwrap());
    me.extend(one);
    for (i, s) in inputs.iter().enumerate() {
        me.extend(hex::decode(vk::IC[i + 1]).unwrap());
        me.extend(s);
    }
    let vk_x = env::alt_bn128_g1_multiexp(&me);
    let mut neg = vec![1u8];
    neg.extend(a);
    let neg_a = env::alt_bn128_g1_sum(&neg);
    let mut pc = Vec::with_capacity(4 * 192);
    pc.extend(&neg_a);
    pc.extend(b);
    pc.extend(hex::decode(vk::ALPHA_G1).unwrap());
    pc.extend(hex::decode(vk::BETA_G2).unwrap());
    pc.extend(&vk_x);
    pc.extend(hex::decode(vk::GAMMA_G2).unwrap());
    pc.extend(c);
    pc.extend(hex::decode(vk::DELTA_G2).unwrap());
    env::alt_bn128_pairing_check(&pc)
}
