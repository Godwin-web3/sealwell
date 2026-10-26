//! Sealwell auction contract (testnet prototype, unaudited).
//!
//! Lifecycle per batch `b`:
//! `open_batch` → `submit_bid` (IBE ciphertext + NEAR bond) → after deadline `close_batch`
//! → cross-contract `request_app_private_key` on the NEAR MPC signer (CKD domain)
//! → `on_ckd` unwraps & pairing-verifies the batch key and stores it publicly
//! → `submit_opening` (anyone; checked with FO re-encryption) → after the reveal window
//! `finalize` (uniform-price clearing, bond refunds, slashing, settlement events).
//! If the MPC call fails or times out, the batch becomes `Failed`; anyone may retry `close_batch`
//! (at most `MAX_CKD_ATTEMPTS` times) or call `refund`, which returns bonds and escrowed tokens.
//!
//! Token escrow and settlement go through a NEAR Intents verifier (`intents`): bidders move
//! verifier balances to this contract with `mt_transfer_call` (msg = {batch_id, bid_index});
//! `finalize` pays out with `mt_batch_transfer` on the verifier's internal ledger.

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
const MT_TRANSFER_GAS: Gas = Gas::from_tgas(15);
/// Hard cap on bids per batch: bounds `finalize` (one verifier transfer per paid-out bid)
/// and opening work. Batches may set a lower cap.
pub const MAX_BIDS_HARD_CAP: u32 = 12;
pub const MAX_CKD_ATTEMPTS: u32 = 3;
/// Ciphertext = U (96, compressed G2) ‖ V (32) ‖ AEAD(M) (≥16-byte tag).
pub const CT_MIN_LEN: usize = 96 + 32 + 16;
pub const CT_MAX_LEN: usize = 96 + 32 + 16 + 256;

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
    /// Base / quote token amounts escrowed in this contract's verifier balance for this bid.
    pub escrow_base: U128,
    pub escrow_quote: U128,
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
    /// Verifier token ids, e.g. `nep141:base.testnet`.
    pub base_token: String,
    pub quote_token: String,
    pub max_bids: u32,
    pub ckd_attempts: u32,
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
    /// NEAR Intents verifier used for escrow and settlement.
    intents: AccountId,
}

#[near(serializers = [json])]
pub struct EscrowMsg {
    pub batch_id: U64,
    pub bid_index: u32,
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
    pub fn new(mpc: AccountId, domain_id: u64, mpk: String, treasury: AccountId, intents: AccountId) -> Self {
        let mpk_pt = sealwell_ibe::parse_near_g2(&mpk).expect("bad mpk");
        Self {
            mpc,
            domain_id,
            mpk: sealwell_ibe::g2_to_bytes(&mpk_pt).to_vec(),
            batches: LookupMap::new(Key::Batches),
            next_batch: 0,
            treasury,
            intents,
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

    pub fn open_batch(
        &mut self,
        duration_sec: u64,
        reveal_window_sec: u64,
        min_bond: U128,
        base_token: String,
        quote_token: String,
        max_bids: u32,
    ) -> U64 {
        require!(max_bids > 0 && max_bids <= MAX_BIDS_HARD_CAP, "max_bids out of range");
        require!(base_token != quote_token, "base == quote");
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
                base_token,
                quote_token,
                max_bids,
                ckd_attempts: 0,
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
        require!(ct.len() >= CT_MIN_LEN && ct.len() <= CT_MAX_LEN, "ciphertext length out of range");
        let bidder = env::predecessor_account_id();
        let b = self.batch_mut(batch_id.0);
        require!(b.state == BatchState::Open, "batch not open");
        require!(env::block_timestamp() < b.deadline_ns.0, "deadline passed");
        require!(deposit >= b.min_bond.0, "bond too small");
        require!((b.bids.len() as u32) < b.max_bids, "batch full");
        // U must be a valid compressed G2 point in the prime-order subgroup (host check; panics otherwise).
        let _ = host::g2_decompress(&ct[..96]);
        b.bids.push(Bid {
            bidder,
            ciphertext: ct,
            bond: U128(deposit),
            opened: None,
            settled: false,
            escrow_base: U128(0),
            escrow_quote: U128(0),
        });
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
        require!(b.ckd_attempts < MAX_CKD_ATTEMPTS, "CKD attempts exhausted; call refund");
        b.ckd_attempts += 1;
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
        require!(self.batches.get(&batch_id.0).map(|b| b.state == BatchState::Closing) == Some(true), "not closing");
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
        match order.side {
            clearing::Side::Buy => require!(
                order.price.0.checked_mul(order.qty.0).map_or(false, |n| n <= bid.escrow_quote.0),
                "buy order not covered by quote escrow"
            ),
            clearing::Side::Sell => require!(order.qty.0 <= bid.escrow_base.0, "sell order not covered by base escrow"),
        }
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
        // Payouts per bid from the escrow, in the verifier ledger.
        let n = b.bids.len();
        let mut out_base: Vec<u128> = b.bids.iter().map(|x| x.escrow_base.0).collect();
        let mut out_quote: Vec<u128> = b.bids.iter().map(|x| x.escrow_quote.0).collect();
        if let Some(r) = &result {
            for (i, qty) in &r.fills {
                let o = b.bids[*i].opened.clone().unwrap();
                let notional = qty * r.price; // ≤ escrow, checked at opening
                match o.side {
                    clearing::Side::Buy => { out_base[*i] += qty; out_quote[*i] -= notional; }
                    clearing::Side::Sell => { out_base[*i] -= qty; out_quote[*i] += notional; }
                }
                log!(
                    "EVENT_JSON:{{\"event\":\"fill\",\"batch\":{},\"bid\":{},\"account\":\"{}\",\"side\":\"{:?}\",\"qty\":\"{}\",\"price\":\"{}\"}}",
                    batch_id.0, i, b.bids[*i].bidder, o.side, qty, r.price
                );
            }
        }
        let (base_t, quote_t) = (b.base_token.clone(), b.quote_token.clone());
        let mut transfers = vec![];
        for i in 0..n {
            transfers.push((b.bids[i].bidder.clone(), out_base[i], out_quote[i]));
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
        for (who, base_amt, quote_amt) in transfers {
            self.pay_out(&who, &base_t, base_amt, &quote_t, quote_amt, batch_id.0);
        }
        let b = self.batch_mut(batch_id.0);
        b.state = BatchState::Finalized;
        b.clearing_price
    }

    /// If the MPC never released the key, return every bond.
    pub fn refund(&mut self, batch_id: U64) {
        let b = self.batch_mut(batch_id.0);
        require!(b.state == BatchState::Failed, "only failed batches refund");
        let (base_t, quote_t) = (b.base_token.clone(), b.quote_token.clone());
        let mut transfers = vec![];
        for bid in b.bids.iter_mut() {
            if !bid.settled {
                bid.settled = true;
                let _ = Promise::new(bid.bidder.clone()).transfer(NearToken::from_yoctonear(bid.bond.0));
                transfers.push((bid.bidder.clone(), bid.escrow_base.0, bid.escrow_quote.0));
            }
        }
        b.state = BatchState::Finalized;
        log!("EVENT_JSON:{{\"event\":\"batch_refunded\",\"batch\":{}}}", batch_id.0);
        for (who, ba, qa) in transfers {
            self.pay_out(&who, &base_t, ba, &quote_t, qa, batch_id.0);
        }
    }

    // ---------------- NEAR Intents escrow (NEP-245 receiver) ----------------

    /// Called by the verifier when a bidder does
    /// `intents.mt_transfer_call(receiver_id = this, token_id, amount, msg = {"batch_id","bid_index"})`.
    /// Returns the amounts to refund (none on success; any panic makes the verifier refund all).
    pub fn mt_on_transfer(
        &mut self,
        sender_id: AccountId,
        previous_owner_ids: Vec<AccountId>,
        token_ids: Vec<String>,
        amounts: Vec<U128>,
        msg: String,
    ) -> Vec<U128> {
        require!(env::predecessor_account_id() == self.intents, "only the intents verifier");
        require!(previous_owner_ids.iter().all(|o| *o == sender_id), "escrow must come from the bidder");
        let m: EscrowMsg = near_sdk::serde_json::from_str(&msg).expect("msg must be {batch_id, bid_index}");
        let b = self.batch_mut(m.batch_id.0);
        require!(b.state == BatchState::Open && env::block_timestamp() < b.deadline_ns.0, "batch not open");
        let (base_t, quote_t) = (b.base_token.clone(), b.quote_token.clone());
        let bid = b.bids.get_mut(m.bid_index as usize).expect("no such bid");
        require!(bid.bidder == sender_id, "not your bid");
        for (t, a) in token_ids.iter().zip(amounts.iter()) {
            if *t == base_t {
                bid.escrow_base = U128(bid.escrow_base.0.checked_add(a.0).expect("overflow"));
            } else if *t == quote_t {
                bid.escrow_quote = U128(bid.escrow_quote.0.checked_add(a.0).expect("overflow"));
            } else {
                env::panic_str("token not in this batch's pair");
            }
        }
        log!("EVENT_JSON:{{\"event\":\"escrowed\",\"batch\":{},\"bid\":{},\"base\":\"{}\",\"quote\":\"{}\"}}",
            m.batch_id.0, m.bid_index, bid.escrow_base.0, bid.escrow_quote.0);
        vec![U128(0); amounts.len()]
    }

    fn pay_out(&self, who: &AccountId, base_t: &str, base_amt: u128, quote_t: &str, quote_amt: u128, batch: u64) {
        let mut ids = vec![];
        let mut amts = vec![];
        if base_amt > 0 { ids.push(base_t.to_string()); amts.push(U128(base_amt)); }
        if quote_amt > 0 { ids.push(quote_t.to_string()); amts.push(U128(quote_amt)); }
        if ids.is_empty() { return; }
        let args = near_sdk::serde_json::json!({
            "receiver_id": who, "token_ids": ids, "amounts": amts,
            "memo": format!("sealwell batch {batch}"),
        });
        let _ = Promise::new(self.intents.clone()).function_call(
            "mt_batch_transfer".to_string(),
            near_sdk::serde_json::to_vec(&args).unwrap(),
            NearToken::from_yoctonear(1),
            MT_TRANSFER_GAS,
        );
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

    // ---------------- lifecycle tests (mocked chain) ----------------
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, PromiseResult};

    const ME: &str = "auction.testnet";
    const INTENTS: &str = "intents.sw.testnet";
    const BASE: &str = "nep141:base.sw.testnet";
    const QUOTE: &str = "nep141:quote.sw.testnet";
    const BOND: u128 = 10u128.pow(22);

    fn acc(s: &str) -> AccountId { s.parse().unwrap() }

    fn ctx(pred: &str, deposit: u128, ts_sec: u64) -> VMContextBuilder {
        let mut c = VMContextBuilder::new();
        c.current_account_id(acc(ME))
            .predecessor_account_id(acc(pred))
            .signer_account_id(acc(pred))
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .block_timestamp(ts_sec * 1_000_000_000)
            .account_balance(NearToken::from_near(100));
        c
    }

    struct Env { c: Contract, msk: Fr, mpk: G2Affine, rng: StdRng }

    fn setup(max_bids: u32) -> Env {
        let mut rng = StdRng::seed_from_u64(42);
        let msk = Fr::rand(&mut rng);
        let mpk = (G2Affine::generator() * msk).into_affine();
        testing_env!(ctx("owner.testnet", 0, 0).build());
        let mut c = Contract::new(acc("mpc.testnet"), 2, sealwell_ibe::format_near_g2(&mpk), acc("treasury.testnet"), acc(INTENTS));
        c.open_batch(100, 100, U128(BOND), BASE.into(), QUOTE.into(), max_bids);
        Env { c, msk, mpk, rng }
    }

    fn seal(e: &mut Env, order: &str) -> (String, [u8; 32]) {
        let app_id = sealwell_ibe::derive_app_id(ME, &batch_path(0));
        let (ct, sigma) = sealwell_ibe::encrypt(&mut e.rng, &e.mpk, &app_id, order.as_bytes());
        (hex::encode(ct.to_bytes()), sigma)
    }

    fn bid(e: &mut Env, who: &str, order: &str) -> (u32, [u8; 32]) {
        let (ct, sigma) = seal(e, order);
        testing_env!(ctx(who, BOND, 10).build());
        (e.c.submit_bid(U64(0), ct), sigma)
    }

    fn escrow(e: &mut Env, who: &str, idx: u32, token: &str, amt: u128) {
        testing_env!(ctx(INTENTS, 0, 20).build());
        let msg = format!("{{\"batch_id\":\"0\",\"bid_index\":{idx}}}");
        let r = e.c.mt_on_transfer(acc(who), vec![acc(who)], vec![token.into()], vec![U128(amt)], msg);
        assert_eq!(r, vec![U128(0)]);
    }

    fn close(e: &mut Env) {
        testing_env!(ctx("keeper.testnet", 0, 200).build());
        let _ = e.c.close_batch(U64(0));
    }

    fn ckd_response(e: &Env) -> CkdResponse {
        let app_id = sealwell_ibe::derive_app_id(ME, &batch_path(0));
        let h = sealwell_ibe::identity_point(&e.mpk, &app_id);
        let a = app_scalar(ME, 0);
        let y = (G1Affine::generator() * Fr::from(777u64)).into_affine();
        let c = ((h * e.msk) + y * a).into_affine();
        CkdResponse { big_y: sealwell_ibe::format_near_g1(&y), big_c: sealwell_ibe::format_near_g1(&c) }
    }

    fn callback(e: &mut Env, ok: bool) -> bool {
        let mut b = ctx(ME, 0, 201);
        let res = if ok {
            let r = ckd_response(e);
            b.build();
            testing_env!(b.build(), near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(),
                vec![PromiseResult::Successful(near_sdk::serde_json::to_vec(&r).unwrap())]);
            Ok(r)
        } else {
            testing_env!(b.build(), near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(),
                vec![PromiseResult::Failed]);
            Err(PromiseError::Failed)
        };
        e.c.on_ckd(U64(0), res)
    }

    fn state(e: &Env) -> BatchState { e.c.get_batch(U64(0)).unwrap().state }

    #[test]
    fn mpc_failure_then_refund_returns_all_bonds_and_escrow() {
        let mut e = setup(5);
        let (i0, _) = bid(&mut e, "alice.testnet", r#"{"side":"buy","price":"90","qty":"10"}"#);
        let (i1, _) = bid(&mut e, "bob.testnet", r#"{"side":"sell","price":"80","qty":"6"}"#);
        escrow(&mut e, "alice.testnet", i0, QUOTE, 900);
        escrow(&mut e, "bob.testnet", i1, BASE, 6);
        close(&mut e);
        assert_eq!(state(&e), BatchState::Closing);
        assert!(!callback(&mut e, false)); // simulated MPC error / timeout
        assert_eq!(state(&e), BatchState::Failed);
        testing_env!(ctx("anyone.testnet", 0, 300).build());
        e.c.refund(U64(0));
        let b = e.c.get_batch(U64(0)).unwrap();
        assert_eq!(b.state, BatchState::Finalized);
        assert!(b.bids.iter().all(|x| x.settled));
        // receipts: 2 NEAR bond transfers + 2 verifier mt_batch_transfer calls
        let receipts = near_sdk::test_utils::get_created_receipts();
        let to_intents = receipts.iter().filter(|r| r.receiver_id.as_str() == INTENTS).count();
        let bonds = receipts.iter().filter(|r| r.receiver_id.as_str().ends_with("alice.testnet") || r.receiver_id.as_str() == "bob.testnet").count();
        assert_eq!((to_intents, bonds), (2, 2));
        // a refunded batch cannot be refunded or closed again
        testing_env!(ctx("anyone.testnet", 0, 301).build());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.refund(U64(0)))).is_err());
    }

    #[test]
    fn failed_batch_can_be_reclosed_then_succeeds_and_attempts_are_capped() {
        let mut e = setup(5);
        bid(&mut e, "alice.testnet", r#"{"side":"buy","price":"90","qty":"10"}"#);
        for _ in 0..2 { close(&mut e); callback(&mut e, false); assert_eq!(state(&e), BatchState::Failed); }
        close(&mut e);
        assert!(callback(&mut e, true));
        assert_eq!(state(&e), BatchState::Revealed);
        let mut e = setup(5);
        for _ in 0..MAX_CKD_ATTEMPTS { close(&mut e); callback(&mut e, false); }
        testing_env!(ctx("keeper.testnet", 0, 200).build());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { let _ = e.c.close_batch(U64(0)); })).is_err());
    }

    #[test]
    fn bid_cap_and_ciphertext_format_enforced() {
        let mut e = setup(2);
        bid(&mut e, "a.testnet", r#"{"side":"buy","price":"1","qty":"1"}"#);
        bid(&mut e, "b.testnet", r#"{"side":"buy","price":"1","qty":"1"}"#);
        let (ct, _) = seal(&mut e, "x");
        testing_env!(ctx("c.testnet", BOND, 10).build());
        let full = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.submit_bid(U64(0), ct.clone())));
        assert!(full.is_err(), "third bid must hit max_bids");
        let mut e = setup(5);
        testing_env!(ctx("c.testnet", BOND, 10).build());
        let short = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.submit_bid(U64(0), "00".repeat(100))));
        assert!(short.is_err());
        let mut bad = hex::decode(&ct).unwrap(); bad[5] ^= 0xff; // not a G2 point
        let junk = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.submit_bid(U64(0), hex::encode(&bad))));
        assert!(junk.is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| setup(MAX_BIDS_HARD_CAP + 1))).is_err());
    }

    #[test]
    fn escrow_only_from_verifier_and_bidder() {
        let mut e = setup(5);
        let (i0, _) = bid(&mut e, "alice.testnet", r#"{"side":"buy","price":"90","qty":"10"}"#);
        testing_env!(ctx("evil.testnet", 0, 20).build());
        let msg = r#"{"batch_id":"0","bid_index":0}"#.to_string();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.mt_on_transfer(acc("alice.testnet"), vec![acc("alice.testnet")], vec![QUOTE.into()], vec![U128(1)], msg.clone()))).is_err());
        testing_env!(ctx(INTENTS, 0, 20).build());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.mt_on_transfer(acc("bob.testnet"), vec![acc("bob.testnet")], vec![QUOTE.into()], vec![U128(1)], msg.clone()))).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.mt_on_transfer(acc("alice.testnet"), vec![acc("alice.testnet")], vec!["nep141:other.testnet".into()], vec![U128(1)], msg.clone()))).is_err());
        escrow(&mut e, "alice.testnet", i0, QUOTE, 900);
        assert_eq!(e.c.get_batch(U64(0)).unwrap().bids[0].escrow_quote, U128(900));
    }

    #[test]
    fn full_lifecycle_settles_from_escrow_and_rejects_underfunded_opening() {
        let mut e = setup(5);
        let ob = r#"{"side":"buy","price":"90","qty":"10"}"#;
        let os = r#"{"side":"sell","price":"80","qty":"6"}"#;
        let ou = r#"{"side":"buy","price":"100","qty":"5"}"#;
        let (i0, s0) = bid(&mut e, "alice.testnet", ob);
        let (i1, s1) = bid(&mut e, "bob.testnet", os);
        let (i2, s2) = bid(&mut e, "carol.testnet", ou);
        escrow(&mut e, "alice.testnet", i0, QUOTE, 1000);
        escrow(&mut e, "bob.testnet", i1, BASE, 6);
        escrow(&mut e, "carol.testnet", i2, QUOTE, 499); // < 100*5
        close(&mut e);
        assert!(callback(&mut e, true));
        testing_env!(ctx("keeper.testnet", 0, 210).build());
        e.c.submit_opening(U64(0), i0, ob.into(), hex::encode(s0));
        e.c.submit_opening(U64(0), i1, os.into(), hex::encode(s1));
        let under = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.c.submit_opening(U64(0), i2, ou.into(), hex::encode(s2))));
        assert!(under.is_err(), "underfunded buy must not open");
        testing_env!(ctx("keeper.testnet", 0, 400).build());
        // tie-break: volume 6 at every price in [80, 90] → lowest (80)
        assert_eq!(e.c.finalize(U64(0)), Some(U128(80)));
        let receipts = near_sdk::test_utils::get_created_receipts();
        let calls: Vec<String> = receipts.iter().filter(|r| r.receiver_id.as_str() == INTENTS).flat_map(|r| r.actions.iter()).filter_map(|a| match a {
            near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. } => Some(format!("{}:{}", String::from_utf8_lossy(method_name), String::from_utf8_lossy(args))),
            _ => None,
        }).collect();
        // alice: +6 base, 1000-480 quote; bob: +480 quote; carol: refund 499 quote
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("alice") && c.contains("\"6\"") && c.contains("\"520\"")), "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("bob") && c.contains("\"480\"") && !c.contains(BASE)), "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("carol") && c.contains("\"499\"")), "{calls:?}");
    }
}
