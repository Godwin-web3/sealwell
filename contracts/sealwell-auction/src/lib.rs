//! Sealwell auction contract (testnet prototype, unaudited).
//!
//! Lifecycle per batch `b`:
//! `open_batch` → `submit_bid` (IBE ciphertext + NEAR bond) → after deadline `close_batch`
//! → cross-contract `request_app_private_key` on the NEAR MPC signer (CKD domain)
//! → `on_ckd` unwraps & pairing-verifies the batch key and stores it publicly
//! → `submit_opening` (anyone; checked with FO re-encryption) → after the reveal window
//! `finalize` (uniform-price clearing, bond refunds, slashing, settlement events).
//! If the MPC call fails or times out, the batch becomes `Failed` and `refund` returns bonds.

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use near_sdk::json_types::{U128, U64};

use near_sdk::store::LookupMap;
use near_sdk::{
    env, log, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError,
};
use sha2::{Digest, Sha256};

pub mod clearing;
use clearing::{clear_uniform, Order};
mod host;

const CKD_GAS: Gas = Gas::from_tgas(50);
const CALLBACK_GAS: Gas = Gas::from_tgas(60);

#[derive(BorshStorageKey)]
#[near]
enum Key {
    Batches,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub enum BatchState {
    Open,
    Closing,
    Revealed,
    Failed,
    Finalized,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Bid {
    pub bidder: AccountId,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
    pub bond: U128,
    pub opened: Option<Order>,
    pub settled: bool,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Batch {
    pub id: U64,
    pub deadline_ns: U64,
    pub reveal_window_ns: U64,
    pub min_bond: U128,
    pub state: BatchState,
    pub revealed_at_ns: Option<U64>,
    /// Released, pairing-verified identity key `sk_b` (compressed G1, hex). Public by design.
    pub batch_key: Option<String>,
    pub clearing_price: Option<U128>,
    pub bids: Vec<Bid>,
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct CkdResponse {
    pub big_y: String,
    pub big_c: String,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    mpc: AccountId,
    domain_id: u64,
    /// MPC CKD master public key (compressed G2, 96 bytes).
    mpk: Vec<u8>,
    batches: LookupMap<u64, Batch>,
    next_batch: u64,
    treasury: AccountId,
}

mod hex_bytes {
    use near_sdk::serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(near_sdk::serde::de::Error::custom)
    }
}

/// CKD derivation path for batch `b`.
pub fn batch_path(b: u64) -> String {
    format!("sealwell/batch/{b}")
}

/// Public app scalar `a = SHA-256-wide("sealwell/v1/a" ‖ contract ‖ "," ‖ b) mod r`.
/// Public on purpose: with a public `a`, the CKD output `(Y, C)` reveals `sk_b` to everyone.
pub fn app_scalar(contract: &str, b: u64) -> Fr {
    let mut wide = Vec::with_capacity(64);
    for i in 0u8..2 {
        let mut h = Sha256::new();
        h.update(b"sealwell/v1/a");
        h.update([i]);
        h.update(contract.as_bytes());
        h.update(b",");
        h.update(b.to_le_bytes());
        wide.extend_from_slice(&h.finalize());
    }
    Fr::from_le_bytes_mod_order(&wide)
}

fn g1_uncompressed(p: &G1Affine) -> Vec<u8> {
    let mut v = Vec::with_capacity(96);
    p.serialize_uncompressed(&mut v).unwrap();
    v
}
fn g2_uncompressed(p: &G2Affine) -> Vec<u8> {
    let mut v = Vec::with_capacity(192);
    p.serialize_uncompressed(&mut v).unwrap();
    v
}

/// Host-function pairing check `e(key, G2) == e(H, mpk)` ⇔ `e(key, −G2)·e(H, mpk) == 1`.
pub fn host_verify_key(key: &G1Affine, h: &G1Affine, mpk: &G2Affine) -> bool {
    let mut input = g1_uncompressed(key);
    input.extend(g2_uncompressed(&(-G2Affine::generator())));
    input.extend(g1_uncompressed(h));
    input.extend(g2_uncompressed(mpk));
    env::bls12381_pairing_check(&input)
}

fn near_g1_bytes(s: &str) -> Vec<u8> {
    let b58 = s.strip_prefix("bls12381g1:").expect("bls12381g1: prefix");
    near_sdk::bs58::decode(b58).into_vec().expect("base58")
}

fn gas_used() -> u64 {
    env::used_gas().as_gas()
}

#[near]
impl Contract {
    #[init]
    pub fn new(mpc: AccountId, domain_id: u64, mpk: String, treasury: AccountId) -> Self {
        let mpk_pt = sealwell_ibe::parse_near_g2(&mpk).expect("bad mpk");
        Self {
            mpc,
            domain_id,
            mpk: sealwell_ibe::g2_to_bytes(&mpk_pt).to_vec(),
            batches: LookupMap::new(Key::Batches),
            next_batch: 0,
            treasury,
        }
    }

    fn mpk_point(&self) -> G2Affine {
        host::g2_decompress(&self.mpk)
    }

    fn batch_mut(&mut self, b: u64) -> &mut Batch {
        self.batches.get_mut(&b).expect("no such batch")
    }

    // ---------------- views ----------------

    pub fn get_batch(&self, batch_id: U64) -> Option<Batch> {
        self.batches.get(&batch_id.0).cloned()
    }

    /// Everything a bidder needs to encrypt to batch `b` (identity is fixed before any key exists).
    pub fn batch_identity(&self, batch_id: U64) -> near_sdk::serde_json::Value {
        let me = env::current_account_id();
        let path = batch_path(batch_id.0);
        let app_id = sealwell_ibe::derive_app_id(me.as_str(), &path);
        near_sdk::serde_json::json!({
            "account": me, "path": path, "app_id": hex::encode(app_id),
            "mpk": sealwell_ibe::format_near_g2(&self.mpk_point()),
            "a": hex::encode(app_scalar(me.as_str(), batch_id.0).into_bigint().to_bytes_be()),
        })
    }

    // ---------------- auction ----------------

    pub fn open_batch(&mut self, duration_sec: u64, reveal_window_sec: u64, min_bond: U128) -> U64 {
        let id = self.next_batch;
        self.next_batch += 1;
        let now = env::block_timestamp();
        self.batches.insert(
            id,
            Batch {
                id: U64(id),
                deadline_ns: U64(now + duration_sec * 1_000_000_000),
                reveal_window_ns: U64(reveal_window_sec * 1_000_000_000),
                min_bond,
                state: BatchState::Open,
                revealed_at_ns: None,
                batch_key: None,
                clearing_price: None,
                bids: vec![],
            },
        );
        log!("EVENT_JSON:{{\"event\":\"batch_opened\",\"batch\":{id}}}");
        U64(id)
    }

    /// Submit an IBE ciphertext (hex) with an attached NEAR bond. Returns bid index.
    #[payable]
    pub fn submit_bid(&mut self, batch_id: U64, ciphertext_hex: String) -> u32 {
        let deposit = env::attached_deposit().as_yoctonear();
        let ct = hex::decode(&ciphertext_hex).expect("hex");
        require!(ct.len() <= 1024, "ciphertext too large");
        sealwell_ibe::Ciphertext::from_bytes(&ct).expect("malformed ciphertext");
        let bidder = env::predecessor_account_id();
        let b = self.batch_mut(batch_id.0);
        require!(b.state == BatchState::Open, "batch not open");
        require!(env::block_timestamp() < b.deadline_ns.0, "deadline passed");
        require!(deposit >= b.min_bond.0, "bond too small");
        b.bids.push(Bid { bidder, ciphertext: ct, bond: U128(deposit), opened: None, settled: false });
        (b.bids.len() - 1) as u32
    }

    /// After the deadline, request the batch key from the MPC CKD domain.
    pub fn close_batch(&mut self, batch_id: U64) -> Promise {
        let me = env::current_account_id();
        let domain_id = self.domain_id;
        let mpc = self.mpc.clone();
        let b = self.batch_mut(batch_id.0);
        require!(
            b.state == BatchState::Open || b.state == BatchState::Failed,
            "batch not closable"
        );
        require!(env::block_timestamp() >= b.deadline_ns.0, "deadline not reached");
        b.state = BatchState::Closing;
        let a = app_scalar(me.as_str(), batch_id.0);
        let pk1 = host::g1_msm(&[(G1Affine::generator(), a)]);
        let pk2 = host::g2_msm(&[(G2Affine::generator(), a)]);
        let args = near_sdk::serde_json::json!({ "request": {
            "app_public_key": { "AppPublicKeyPV": {
                "pk1": sealwell_ibe::format_near_g1(&pk1),
                "pk2": sealwell_ibe::format_near_g2(&pk2) } },
            "derivation_path": batch_path(batch_id.0),
            "domain_id": domain_id,
        }});
        log!("gas before CKD promise: {}", gas_used());
        Promise::new(mpc)
            .function_call(
                "request_app_private_key".to_string(),
                near_sdk::serde_json::to_vec(&args).unwrap(),
                NearToken::from_yoctonear(1),
                CKD_GAS,
            )
            .then(Self::ext(me).with_static_gas(CALLBACK_GAS).on_ckd(batch_id))
    }

    #[private]
    pub fn on_ckd(
        &mut self,
        batch_id: U64,
        #[callback_result] res: Result<CkdResponse, PromiseError>,
    ) -> bool {
        let me = env::current_account_id();
        let mpk = self.mpk_point();
        let g0 = gas_used();
        let out = match res {
            Ok(o) => o,
            Err(_) => {
                self.batch_mut(batch_id.0).state = BatchState::Failed;
                log!("EVENT_JSON:{{\"event\":\"ckd_failed\",\"batch\":{}}}", batch_id.0);
                return false;
            }
        };
        let a = app_scalar(me.as_str(), batch_id.0);
        let y = host::g1_decompress(&near_g1_bytes(&out.big_y));
        let c = host::g1_decompress(&near_g1_bytes(&out.big_c));
        let key = host::g1_msm(&[(c, Fr::from(1u64)), (y, -a)]);
        let g1 = gas_used();
        let app_id = sealwell_ibe::derive_app_id(me.as_str(), &batch_path(batch_id.0));
        let h = host::identity_point(&mpk, &app_id);
        let g2 = gas_used();
        let ok = !key.is_zero() && host_verify_key(&key, &h, &mpk);
        let g3 = gas_used();
        log!(
            "gas: unwrap(C-aY)={} hash_to_curve={} host_pairing_check={}",
            g1 - g0, g2 - g1, g3 - g2
        );
        let b = self.batch_mut(batch_id.0);
        if !ok {
            b.state = BatchState::Failed;
            log!("EVENT_JSON:{{\"event\":\"ckd_bad_key\",\"batch\":{}}}", batch_id.0);
            return false;
        }
        b.state = BatchState::Revealed;
        b.revealed_at_ns = Some(U64(env::block_timestamp()));
        let key_hex = hex::encode(sealwell_ibe::g1_to_bytes(&key));
        log!(
            "EVENT_JSON:{{\"event\":\"batch_key_released\",\"batch\":{},\"key\":\"{}\",\"app_id\":\"{}\"}}",
            batch_id.0, key_hex, hex::encode(app_id)
        );
        b.batch_key = Some(key_hex);
        true
    }

    /// Anyone (usually a keeper) submits the opening of bid `bid_index`.
    /// Checked by deterministic FO re-encryption (`sealwell_ibe::verify_opening`), so only the
    /// unique plaintext the ciphertext commits to is accepted.
    pub fn submit_opening(
        &mut self,
        batch_id: U64,
        bid_index: u32,
        plaintext: String,
        sigma_hex: String,
    ) -> Order {
        let me = env::current_account_id();
        let b = self.batches.get(&batch_id.0).expect("no such batch");
        require!(b.state == BatchState::Revealed, "batch key not released");
        require!(
            env::block_timestamp() < b.revealed_at_ns.unwrap().0 + b.reveal_window_ns.0,
            "reveal window over"
        );
        let bid = b.bids.get(bid_index as usize).expect("no such bid");
        require!(bid.opened.is_none(), "already opened");
        let sigma: [u8; 32] = hex::decode(&sigma_hex).expect("hex").try_into().expect("sigma len");
        let ctb = &bid.ciphertext;
        require!(ctb.len() >= 96 + 32 + 16, "ciphertext too short");
        let app_id = sealwell_ibe::derive_app_id(me.as_str(), &batch_path(batch_id.0));
        let key_bytes = hex::decode(b.batch_key.as_ref().unwrap()).unwrap();
        let g0 = gas_used();
        // (1) U == H3(σ, M, app_id)·G2, via host multiexp.
        let r = sealwell_ibe::opening_scalar(&app_id, plaintext.as_bytes(), &sigma);
        let u = host::g2_msm(&[(G2Affine::generator(), r)]);
        require!(sealwell_ibe::g2_to_bytes(&u)[..] == ctb[..96], "opening does not match ciphertext (U)");
        let g1 = gas_used();
        // (2) V ⊕ H2(e(sk_b, U)) == σ and the AEAD opens to M (one in-Wasm pairing).
        let key = host::g1_decompress(&key_bytes);
        let v: [u8; 32] = ctb[96..128].try_into().unwrap();
        require!(
            sealwell_ibe::verify_opening_with_key(&app_id, &key, &u, &v, &ctb[128..], plaintext.as_bytes(), &sigma),
            "opening does not match ciphertext (V/W)"
        );
        log!("gas: opening U-check(host)={} pairing+mask+aead={}", g1 - g0, gas_used() - g1);
        let order: Order = near_sdk::serde_json::from_str(&plaintext).expect("plaintext is not an order");
        require!(order.qty.0 > 0 && order.price.0 > 0, "empty order");
        let b = self.batch_mut(batch_id.0);
        b.bids[bid_index as usize].opened = Some(order.clone());
        order
    }

    /// After the reveal window: clear at a uniform price, refund bonds of opened bids,
    /// slash unopened ones to the treasury, emit settlement events (settlement is mocked).
    pub fn finalize(&mut self, batch_id: U64) -> Option<U128> {
        let treasury = self.treasury.clone();
        let b = self.batch_mut(batch_id.0);
        require!(b.state == BatchState::Revealed, "not revealed");
        require!(
            env::block_timestamp() >= b.revealed_at_ns.unwrap().0 + b.reveal_window_ns.0,
            "reveal window still open"
        );
        let orders: Vec<(usize, Order)> = b
            .bids
            .iter()
            .enumerate()
            .filter_map(|(i, x)| x.opened.clone().map(|o| (i, o)))
            .collect();
        let result = clear_uniform(&orders);
        b.clearing_price = result.as_ref().map(|r| U128(r.price));
        if let Some(r) = &result {
            for (i, qty) in &r.fills {
                let bid = &b.bids[*i];
                let o = bid.opened.as_ref().unwrap();
                log!(
                    "EVENT_JSON:{{\"event\":\"settle_mocked\",\"batch\":{},\"bid\":{},\"account\":\"{}\",\"side\":\"{:?}\",\"qty\":\"{}\",\"price\":\"{}\"}}",
                    batch_id.0, i, bid.bidder, o.side, qty, r.price
                );
            }
        }
        let mut slashed = 0u128;
        for (i, bid) in b.bids.iter_mut().enumerate() {
            if bid.settled { continue; }
            bid.settled = true;
            if bid.opened.is_some() {
                let _ = Promise::new(bid.bidder.clone()).transfer(NearToken::from_yoctonear(bid.bond.0));
            } else {
                slashed += bid.bond.0;
                log!("EVENT_JSON:{{\"event\":\"bond_slashed\",\"batch\":{},\"bid\":{},\"account\":\"{}\"}}", batch_id.0, i, bid.bidder);
            }
        }
        if slashed > 0 {
            let _ = Promise::new(treasury).transfer(NearToken::from_yoctonear(slashed));
        }
        b.state = BatchState::Finalized;
        b.clearing_price
    }

    /// If the MPC never released the key, return every bond.
    pub fn refund(&mut self, batch_id: U64) {
        let b = self.batch_mut(batch_id.0);
        require!(b.state == BatchState::Failed, "only failed batches refund");
        for bid in b.bids.iter_mut() {
            if !bid.settled {
                bid.settled = true;
                let _ = Promise::new(bid.bidder.clone()).transfer(NearToken::from_yoctonear(bid.bond.0));
            }
        }
        b.state = BatchState::Finalized;
    }

    // ---------------- gas benchmarks (no state change) ----------------

    pub fn bench_hash_to_curve(&self, path: String) -> String {
        let app_id = sealwell_ibe::derive_app_id(env::current_account_id().as_str(), &path);
        let mpk = self.mpk_point();
        let g0 = gas_used();
        let h = sealwell_ibe::identity_point(&mpk, &app_id);
        let g1 = gas_used();
        let h2 = host::identity_point(&mpk, &app_id);
        let g2 = gas_used();
        require!(h == h2, "host hash_to_curve mismatch");
        log!("gas: hash_to_curve wasm(arkworks)={} host(map_fp_to_g1+p1_sum)={}", g1 - g0, g2 - g1);
        hex::encode(sealwell_ibe::g1_to_bytes(&h))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn host_pairing_check_accepts_real_key_and_rejects_wrong() {
        let mut rng = StdRng::seed_from_u64(9);
        let msk = Fr::rand(&mut rng);
        let mpk = (G2Affine::generator() * msk).into_affine();
        let app_id = sealwell_ibe::derive_app_id("auction.testnet", &batch_path(0));
        let h = sealwell_ibe::identity_point(&mpk, &app_id);
        let key = (h * msk).into_affine();
        assert!(host_verify_key(&key, &h, &mpk));
        let wrong = (h * (msk + Fr::from(1u64))).into_affine();
        assert!(!host_verify_key(&wrong, &h, &mpk));
    }

    #[test]
    fn host_paths_match_arkworks() {
        let mut rng = StdRng::seed_from_u64(5);
        let msk = Fr::rand(&mut rng);
        let mpk = (G2Affine::generator() * msk).into_affine();
        let app_id = sealwell_ibe::derive_app_id("auction.testnet", &batch_path(7));
        let h = sealwell_ibe::identity_point(&mpk, &app_id);
        assert_eq!(host::identity_point(&mpk, &app_id), h);
        // CKD unwrap C - a*Y via host multiexp
        let a = app_scalar("auction.testnet", 7);
        let y = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();
        let c = ((h * msk) + y * a).into_affine();
        assert_eq!(host::g1_msm(&[(c, Fr::from(1u64)), (y, -a)]), sealwell_ibe::ckd_unwrap(&a, &y, &c));
        assert_eq!(host::g2_msm(&[(G2Affine::generator(), a)]), sealwell_ibe::app_public_key_pv(&a).1);
        assert_eq!(host::g2_decompress(&sealwell_ibe::g2_to_bytes(&mpk)), mpk);
    }

    #[test]
    fn app_scalar_is_per_contract_and_batch() {
        assert_ne!(app_scalar("a.testnet", 0), app_scalar("a.testnet", 1));
        assert_ne!(app_scalar("a.testnet", 0), app_scalar("b.testnet", 0));
    }
}
