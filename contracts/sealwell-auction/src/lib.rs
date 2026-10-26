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
//! verifier balances to this contract with `mt_batch_transfer_call` (one fixed base+quote bundle per bid) (msg = {batch_id, bid_index});
//! `finalize` pays out with `mt_batch_transfer` on the verifier's internal ledger.

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use near_sdk::json_types::{U128, U64};

use near_sdk::store::{LookupMap, LookupSet};
use near_sdk::{
    env, log, near, require, AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault,
    Promise, PromiseError,
};
use sha2::{Digest, Sha256};

pub mod clearing;
use clearing::{clear_uniform, Order};
mod host;
pub mod vk;
pub mod zk;
pub mod poseidon_consts;

const CKD_GAS: Gas = Gas::from_tgas(50);
const CALLBACK_GAS: Gas = Gas::from_tgas(60);
const MT_TRANSFER_GAS: Gas = Gas::from_tgas(15);
/// Hard cap on bids per batch: bounds `finalize` (one verifier transfer per paid-out bid)
/// and opening work. Batches may set a lower cap.
pub const MAX_BIDS_HARD_CAP: u32 = 12;
pub const MAX_CKD_ATTEMPTS: u32 = 3;

#[derive(BorshStorageKey)]
#[near]
enum Key {
    Batches,
    Nullifiers,
    PendingDeposits,
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
    /// Shielded bids: relayer that submitted it and its fee (yoctoNEAR, paid from the returned bond).
    pub relayer: Option<AccountId>,
    pub fee: U128,
}

/// Shielded deposit pool: one fixed bundle per note, shared by all pool batches.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PoolConfig {
    pub base_token: String,
    pub quote_token: String,
    pub max_qty: U128,
    pub max_price: U128,
    pub bond: U128,
}

#[near(serializers = [borsh])]
pub struct Pool {
    pub cfg: PoolConfig,
    pub tree: zk::Tree,
    pub leaves: Vec<[u8; 32]>,
    pub nullifiers: LookupSet<[u8; 32]>,
    /// commitment -> depositor, after the NEAR bond and before the token bundle arrives.
    pub pending: LookupMap<[u8; 32], AccountId>,
}

#[near(serializers = [json])]
pub struct PoolDepositMsg {
    pub deposit: String,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Batch {
    pub id: U64,
    pub deadline_ns: U64,
    pub reveal_window_ns: U64,
    /// Exact NEAR bond every bid must attach (identical for all bids).
    pub bond: U128,
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
    /// Largest allowed order (per bid). Every bid escrows the same bundle:
    /// `max_qty` base AND `max_qty * max_price` quote, whatever its side or size.
    pub max_qty: U128,
    pub max_price: U128,
    pub escrow_base_unit: U128,
    pub escrow_quote_unit: U128,
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
    pool: Option<Pool>,
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
            pool: None,
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
        bond: U128,
        base_token: String,
        quote_token: String,
        max_bids: u32,
        max_qty: U128,
        max_price: U128,
    ) -> U64 {
        require!(max_qty.0 > 0 && max_price.0 > 0, "max_qty/max_price must be > 0");
        let quote_unit = max_qty.0.checked_mul(max_price.0).expect("max notional overflows");
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
                bond,
                state: BatchState::Open,
                revealed_at_ns: None,
                batch_key: None,
                clearing_price: None,
                bids: vec![],
                base_token,
                quote_token,
                max_bids,
                max_qty,
                max_price,
                escrow_base_unit: max_qty,
                escrow_quote_unit: U128(quote_unit),
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
        require!(ct.len() == sealwell_ibe::ORDER_CT_LEN, "ciphertext must be exactly ORDER_CT_LEN bytes (padded order)");
        let bidder = env::predecessor_account_id();
        let b = self.batch_mut(batch_id.0);
        require!(b.state == BatchState::Open, "batch not open");
        require!(env::block_timestamp() < b.deadline_ns.0, "deadline passed");
        require!(deposit == b.bond.0, "bond must equal the batch bond exactly");
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
            relayer: None,
            fee: U128(0),
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
        let padded = sealwell_ibe::pad_order(plaintext.as_bytes()).expect("order too long or has trailing spaces");
        let sigma: [u8; 32] = hex::decode(&sigma_hex).expect("hex").try_into().expect("sigma len");
        let ctb = &bid.ciphertext;
        require!(ctb.len() >= 96 + 32 + 16, "ciphertext too short");
        let app_id = sealwell_ibe::derive_app_id(me.as_str(), &batch_path(batch_id.0));
        let key_bytes = hex::decode(b.batch_key.as_ref().unwrap()).unwrap();
        let g0 = gas_used();
        // (1) U == H3(σ, M, app_id)·G2, via host multiexp.
        let r = sealwell_ibe::opening_scalar(&app_id, &padded, &sigma);
        let u = host::g2_msm(&[(G2Affine::generator(), r)]);
        require!(sealwell_ibe::g2_to_bytes(&u)[..] == ctb[..96], "opening does not match ciphertext (U)");
        let g1 = gas_used();
        // (2) V ⊕ H2(e(sk_b, U)) == σ and the AEAD opens to M (one in-Wasm pairing).
        let key = host::g1_decompress(&key_bytes);
        let v: [u8; 32] = ctb[96..128].try_into().unwrap();
        require!(
            sealwell_ibe::verify_opening_with_key(&app_id, &key, &u, &v, &ctb[128..], &padded, &sigma),
            "opening does not match ciphertext (V/W)"
        );
        log!("gas: opening U-check(host)={} pairing+mask+aead={}", g1 - g0, gas_used() - g1);
        let order: Order = near_sdk::serde_json::from_str(&plaintext).expect("plaintext is not an order");
        require!(order.qty.0 > 0 && order.price.0 > 0, "empty order");
        // Every escrowed bid holds the full bundle, so any order within the batch limits is covered.
        require!(bid.escrow_base == b.escrow_base_unit && bid.escrow_quote == b.escrow_quote_unit, "bid has no escrow");
        require!(order.qty.0 <= b.max_qty.0 && order.price.0 <= b.max_price.0, "order exceeds batch limits");
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
                return_bond(bid);
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
                return_bond(bid);
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
        if let Ok(d) = near_sdk::serde_json::from_str::<PoolDepositMsg>(&msg) {
            self.pool_receive(sender_id, d, token_ids, amounts);
            return vec![U128(0); 2];
        }
        let m: EscrowMsg = near_sdk::serde_json::from_str(&msg).expect("msg must be {batch_id, bid_index}");
        let b = self.batch_mut(m.batch_id.0);
        require!(b.state == BatchState::Open && env::block_timestamp() < b.deadline_ns.0, "batch not open");
        let (base_t, quote_t) = (b.base_token.clone(), b.quote_token.clone());
        let (ub, uq) = (b.escrow_base_unit, b.escrow_quote_unit);
        let bid = b.bids.get_mut(m.bid_index as usize).expect("no such bid");
        require!(bid.bidder == sender_id, "not your bid");
        require!(bid.escrow_base.0 == 0 && bid.escrow_quote.0 == 0, "already escrowed");
        // Exactly one bundle, in one call: {base: max_qty, quote: max_qty*max_price}. Same for every bid.
        require!(token_ids.len() == 2 && amounts.len() == 2, "escrow must be one base+quote bundle");
        let got = |t: &str| token_ids.iter().zip(amounts.iter()).find(|(x, _)| x.as_str() == t).map(|(_, a)| *a);
        require!(got(&base_t) == Some(ub) && got(&quote_t) == Some(uq), "escrow must be exactly the batch bundle");
        bid.escrow_base = ub;
        bid.escrow_quote = uq;
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

    // ---------------- shielded pool ----------------

    /// One-time pool setup, by the contract account itself. All pool batches must use these limits.
    pub fn init_pool(&mut self, cfg: PoolConfig) {
        require!(env::predecessor_account_id() == env::current_account_id(), "only self");
        require!(self.pool.is_none(), "pool exists");
        require!(cfg.max_qty.0 > 0 && cfg.max_price.0 > 0 && cfg.base_token != cfg.quote_token, "bad pool config");
        cfg.max_qty.0.checked_mul(cfg.max_price.0).expect("overflow");
        self.pool = Some(Pool {
            cfg,
            tree: zk::Tree::new(),
            leaves: vec![],
            nullifiers: LookupSet::new(Key::Nullifiers),
            pending: LookupMap::new(Key::PendingDeposits),
        });
    }

    pub fn pool_info(&self) -> near_sdk::serde_json::Value {
        let p = self.pool.as_ref().expect("no pool");
        near_sdk::serde_json::json!({
            "cfg": p.cfg, "root": hex::encode(p.tree.root()), "size": p.tree.next_index,
            "leaves": p.leaves.iter().map(hex::encode).collect::<Vec<_>>(),
        })
    }
    pub fn is_spent(&self, nullifier_hash_hex: String) -> bool {
        self.pool.as_ref().expect("no pool").nullifiers.contains(&zk::parse_hex32(&nullifier_hash_hex))
    }

    /// Deposit step 1: attach exactly the pool bond and name the note commitment (LE field hex).
    /// Step 2: `intents.mt_batch_transfer_call(this, [base, quote], [max_qty, max_qty*max_price], msg = {"deposit": commitment})`.
    #[payable]
    pub fn pool_deposit_bond(&mut self, commitment_hex: String) {
        let p = self.pool.as_mut().expect("no pool");
        require!(env::attached_deposit().as_yoctonear() == p.cfg.bond.0, "attach exactly the pool bond");
        let c = zk::parse_hex32(&commitment_hex);
        require!(zk::fr_from_le(&c).is_some(), "commitment not a canonical field element");
        require!(p.pending.get(&c).is_none(), "commitment already pending");
        p.pending.insert(c, env::predecessor_account_id());
    }

    /// Give back the bond of a deposit whose tokens never arrived.
    pub fn pool_cancel_bond(&mut self, commitment_hex: String) {
        let p = self.pool.as_mut().expect("no pool");
        let c = zk::parse_hex32(&commitment_hex);
        require!(p.pending.get(&c) == Some(&env::predecessor_account_id()), "not your pending deposit");
        p.pending.remove(&c);
        let _ = Promise::new(env::predecessor_account_id()).transfer(NearToken::from_yoctonear(p.cfg.bond.0));
    }

    fn pool_receive(&mut self, sender: AccountId, d: PoolDepositMsg, token_ids: Vec<String>, amounts: Vec<U128>) {
        let p = self.pool.as_mut().expect("no pool");
        let c = zk::parse_hex32(&d.deposit);
        require!(p.pending.get(&c) == Some(&sender), "pay the bond first (pool_deposit_bond)");
        let (ub, uq) = (p.cfg.max_qty, U128(p.cfg.max_qty.0 * p.cfg.max_price.0));
        require!(token_ids.len() == 2 && amounts.len() == 2, "deposit must be one base+quote bundle");
        let got = |t: &str| token_ids.iter().zip(amounts.iter()).find(|(x, _)| x.as_str() == t).map(|(_, a)| *a);
        require!(got(&p.cfg.base_token) == Some(ub) && got(&p.cfg.quote_token) == Some(uq), "deposit must be exactly the pool bundle");
        p.pending.remove(&c);
        let g0 = env::used_gas().as_gas();
        let idx = p.tree.insert(zk::fr_from_le(&c).unwrap());
        p.leaves.push(c);
        log!("gas: pool insert (16 Poseidon)={}", env::used_gas().as_gas() - g0);
        log!("EVENT_JSON:{{\"event\":\"pool_deposit\",\"index\":{},\"commitment\":\"{}\",\"root\":\"{}\"}}", idx, d.deposit, hex::encode(p.tree.root()));
    }

    /// Check a spend proof and burn its nullifier. Caller must be the bound relayer.
    fn spend(&mut self, proof_hex: &str, root_hex: &str, nh_hex: &str, ext: [u8; 32]) {
        let p = self.pool.as_mut().expect("no pool");
        let root = zk::parse_hex32(root_hex);
        let nh = zk::parse_hex32(nh_hex);
        require!(p.tree.is_known_root(&root), "unknown or expired root");
        require!(zk::fr_from_le(&nh).is_some(), "nullifier hash not canonical");
        require!(!p.nullifiers.contains(&nh), "note already spent");
        let proof = hex::decode(proof_hex).expect("proof hex");
        let g0 = env::used_gas().as_gas();
        require!(zk::groth16_verify(&proof, &[root, nh, ext]), "invalid proof");
        log!("gas: groth16 verify={}", env::used_gas().as_gas() - g0);
        p.nullifiers.insert(nh);
        log!("EVENT_JSON:{{\"event\":\"nullifier_spent\",\"nullifier_hash\":\"{}\"}}", nh_hex);
    }

    /// Bid from the pool. The proof shows "I own some unspent pool note" without saying which,
    /// and binds (batch, ciphertext, payout, relayer, fee). Submitted by the relayer (predecessor).
    /// The note's bundle and bond become this bid's escrow and bond; payouts go to `payout`.
    pub fn submit_private_bid(
        &mut self,
        batch_id: U64,
        ciphertext_hex: String,
        proof_hex: String,
        root_hex: String,
        nullifier_hash_hex: String,
        payout: AccountId,
        fee: U128,
    ) -> u32 {
        let relayer = env::predecessor_account_id();
        let ct = hex::decode(&ciphertext_hex).expect("hex");
        require!(ct.len() == sealwell_ibe::ORDER_CT_LEN, "ciphertext must be exactly ORDER_CT_LEN bytes (padded order)");
        let cfg = self.pool.as_ref().expect("no pool").cfg.clone();
        require!(fee.0 <= cfg.bond.0, "fee above bond");
        {
            let b = self.batches.get(&batch_id.0).expect("no such batch");
            require!(b.state == BatchState::Open && env::block_timestamp() < b.deadline_ns.0, "batch not open");
            require!((b.bids.len() as u32) < b.max_bids, "batch full");
            require!(
                b.base_token == cfg.base_token && b.quote_token == cfg.quote_token && b.max_qty == cfg.max_qty
                    && b.max_price == cfg.max_price && b.bond == cfg.bond,
                "batch limits differ from the pool"
            );
        }
        let _ = host::g2_decompress(&ct[..96]);
        let ext = zk::ext_hash("bid", batch_id.0, &ct, payout.as_str(), relayer.as_str(), fee.0);
        self.spend(&proof_hex, &root_hex, &nullifier_hash_hex, ext);
        let b = self.batch_mut(batch_id.0);
        let (ub, uq) = (b.escrow_base_unit, b.escrow_quote_unit);
        b.bids.push(Bid {
            bidder: payout,
            ciphertext: ct,
            bond: cfg.bond,
            opened: None,
            settled: false,
            escrow_base: ub,
            escrow_quote: uq,
            relayer: Some(relayer),
            fee,
        });
        (b.bids.len() - 1) as u32
    }

    /// Withdraw an unused note: bundle + bond (minus relayer fee) to `recipient`.
    pub fn pool_withdraw(&mut self, proof_hex: String, root_hex: String, nullifier_hash_hex: String, recipient: AccountId, fee: U128) {
        let relayer = env::predecessor_account_id();
        let cfg = self.pool.as_ref().expect("no pool").cfg.clone();
        require!(fee.0 <= cfg.bond.0, "fee above bond");
        let ext = zk::ext_hash("withdraw", 0, &[], recipient.as_str(), relayer.as_str(), fee.0);
        self.spend(&proof_hex, &root_hex, &nullifier_hash_hex, ext);
        if fee.0 > 0 {
            let _ = Promise::new(relayer).transfer(NearToken::from_yoctonear(fee.0));
        }
        let _ = Promise::new(recipient.clone()).transfer(NearToken::from_yoctonear(cfg.bond.0 - fee.0));
        self.pay_out(&recipient, &cfg.base_token, cfg.max_qty.0, &cfg.quote_token, cfg.max_qty.0 * cfg.max_price.0, u64::MAX);
        log!("EVENT_JSON:{{\"event\":\"pool_withdraw\",\"recipient\":\"{}\"}}", recipient);
    }

    pub fn bench_poseidon(&self, n: u32) -> String {
        let mut x = zk::poseidon(&[ark_bn254::Fr::from(1u64), ark_bn254::Fr::from(2u64)]);
        let g0 = env::used_gas().as_gas();
        for _ in 0..n { x = zk::poseidon(&[x, x]); }
        log!("gas: {} poseidon(2)={}", n, env::used_gas().as_gas() - g0);
        hex::encode(zk::fr_to_le(&x))
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


/// Return a bid's NEAR bond: relayer fee (shielded bids) to the relayer, the rest to the bidder/payout.
fn return_bond(bid: &Bid) {
    let fee = if bid.relayer.is_some() { bid.fee.0.min(bid.bond.0) } else { 0 };
    if fee > 0 {
        let _ = Promise::new(bid.relayer.clone().unwrap()).transfer(NearToken::from_yoctonear(fee));
    }
    let _ = Promise::new(bid.bidder.clone()).transfer(NearToken::from_yoctonear(bid.bond.0 - fee));
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
    const MAXQ: u128 = 10;
    const MAXP: u128 = 100;

    fn acc(s: &str) -> AccountId { s.parse().unwrap() }
    fn fails<R>(f: impl FnOnce() -> R) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).is_err()
    }

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
        c.open_batch(100, 100, U128(BOND), BASE.into(), QUOTE.into(), max_bids, U128(MAXQ), U128(MAXP));
        Env { c, msk, mpk, rng }
    }

    fn seal(e: &mut Env, order: &str) -> (String, [u8; 32]) {
        let app_id = sealwell_ibe::derive_app_id(ME, &batch_path(0));
        let (ct, sigma) = sealwell_ibe::encrypt_order(&mut e.rng, &e.mpk, &app_id, order.as_bytes()).unwrap();
        (hex::encode(ct.to_bytes()), sigma)
    }

    fn bid(e: &mut Env, who: &str, order: &str) -> (u32, [u8; 32]) {
        let (ct, sigma) = seal(e, order);
        testing_env!(ctx(who, BOND, 10).build());
        (e.c.submit_bid(U64(0), ct), sigma)
    }

    fn bundle_args(who: &str, idx: u32) -> (AccountId, Vec<AccountId>, Vec<String>, Vec<U128>, String) {
        (acc(who), vec![acc(who), acc(who)], vec![BASE.into(), QUOTE.into()], vec![U128(MAXQ), U128(MAXQ * MAXP)],
         format!("{{\"batch_id\":\"0\",\"bid_index\":{idx}}}"))
    }

    fn escrow(e: &mut Env, who: &str, idx: u32) {
        testing_env!(ctx(INTENTS, 0, 20).build());
        let (s, p, t, a, m) = bundle_args(who, idx);
        assert_eq!(e.c.mt_on_transfer(s, p, t, a, m), vec![U128(0), U128(0)]);
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
        let b = ctx(ME, 0, 201);
        let res = if ok {
            let r = ckd_response(e);
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

    fn intents_calls() -> Vec<String> {
        near_sdk::test_utils::get_created_receipts().iter().filter(|r| r.receiver_id.as_str() == INTENTS)
            .flat_map(|r| r.actions.clone()).filter_map(|a| match a {
                near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, .. } =>
                    Some(format!("{}:{}", String::from_utf8_lossy(&method_name), String::from_utf8_lossy(&args))),
                _ => None,
            }).collect()
    }

    #[test]
    fn buyer_and_seller_deposits_are_indistinguishable() {
        let mut e = setup(5);
        let (cb, _) = seal(&mut e, r#"{"side":"buy","price":"100","qty":"10"}"#);
        let (cs, _) = seal(&mut e, r#"{"side":"sell","price":"1","qty":"1"}"#);
        assert_eq!(cb.len(), cs.len(), "ciphertext length must not depend on the order");
        assert_eq!(cb.len() / 2, sealwell_ibe::ORDER_CT_LEN);
        testing_env!(ctx("alice.testnet", BOND, 10).build());
        e.c.submit_bid(U64(0), cb);
        testing_env!(ctx("bob.testnet", BOND, 10).build());
        e.c.submit_bid(U64(0), cs);
        escrow(&mut e, "alice.testnet", 0);
        escrow(&mut e, "bob.testnet", 1);
        let b = e.c.get_batch(U64(0)).unwrap();
        let (x, y) = (&b.bids[0], &b.bids[1]);
        assert_eq!((x.bond, x.escrow_base, x.escrow_quote, x.ciphertext.len()), (y.bond, y.escrow_base, y.escrow_quote, y.ciphertext.len()));
        // the escrow call arguments differ only in account and bid index
        let (_, _, ta, aa, _) = bundle_args("alice.testnet", 0);
        let (_, _, tb, ab, _) = bundle_args("bob.testnet", 1);
        assert_eq!((ta, aa), (tb, ab));
    }

    #[test]
    fn deposits_that_would_leak_are_rejected() {
        let mut e = setup(5);
        let (ct, _) = seal(&mut e, r#"{"side":"buy","price":"1","qty":"1"}"#);
        testing_env!(ctx("alice.testnet", BOND + 1, 10).build());
        assert!(fails(|| e.c.submit_bid(U64(0), ct.clone())), "bond must be exact");
        testing_env!(ctx("alice.testnet", BOND, 10).build());
        assert!(fails(|| e.c.submit_bid(U64(0), format!("{ct}00"))), "ciphertext must be constant size");
        let mut bad = hex::decode(&ct).unwrap(); bad[0] &= 0x1f; // clear the compression flag
        assert!(fails(|| e.c.submit_bid(U64(0), hex::encode(&bad))), "U must be a compressed G2 point");
        let mut bad = hex::decode(&ct).unwrap(); bad[1..96].fill(0xff);
        assert!(fails(|| e.c.submit_bid(U64(0), hex::encode(&bad))), "U must decode");
        e.c.submit_bid(U64(0), ct);
        testing_env!(ctx(INTENTS, 0, 20).build());
        let m = r#"{"batch_id":"0","bid_index":0}"#.to_string();
        let a = acc("alice.testnet");
        // quote only (a 'buyer-shaped' deposit), base only, wrong sizes, wrong token, wrong sender, wrong caller
        assert!(fails(|| e.c.mt_on_transfer(a.clone(), vec![a.clone()], vec![QUOTE.into()], vec![U128(MAXQ * MAXP)], m.clone())));
        assert!(fails(|| e.c.mt_on_transfer(a.clone(), vec![a.clone()], vec![BASE.into()], vec![U128(MAXQ)], m.clone())));
        assert!(fails(|| e.c.mt_on_transfer(a.clone(), vec![a.clone(); 2], vec![BASE.into(), QUOTE.into()], vec![U128(MAXQ), U128(500)], m.clone())));
        assert!(fails(|| e.c.mt_on_transfer(a.clone(), vec![a.clone(); 2], vec![BASE.into(), "nep141:x.testnet".into()], vec![U128(MAXQ), U128(MAXQ * MAXP)], m.clone())));
        let (s, p, t, am, _) = bundle_args("bob.testnet", 0);
        assert!(fails(|| e.c.mt_on_transfer(s, p, t, am, m.clone())));
        testing_env!(ctx("evil.testnet", 0, 20).build());
        let (s, p, t, am, mm) = bundle_args("alice.testnet", 0);
        assert!(fails(|| e.c.mt_on_transfer(s, p, t, am, mm)));
        escrow(&mut e, "alice.testnet", 0);
        testing_env!(ctx(INTENTS, 0, 20).build());
        let (s, p, t, am, mm) = bundle_args("alice.testnet", 0);
        assert!(fails(|| e.c.mt_on_transfer(s, p, t, am, mm)), "only one bundle per bid");
    }

    #[test]
    fn mpc_failure_then_refund_returns_all_bonds_and_escrow() {
        let mut e = setup(5);
        let (i0, _) = bid(&mut e, "alice.testnet", r#"{"side":"buy","price":"90","qty":"10"}"#);
        let (i1, _) = bid(&mut e, "bob.testnet", r#"{"side":"sell","price":"80","qty":"6"}"#);
        escrow(&mut e, "alice.testnet", i0);
        escrow(&mut e, "bob.testnet", i1);
        close(&mut e);
        assert_eq!(state(&e), BatchState::Closing);
        assert!(!callback(&mut e, false)); // simulated MPC error / timeout
        assert_eq!(state(&e), BatchState::Failed);
        testing_env!(ctx("anyone.testnet", 0, 300).build());
        e.c.refund(U64(0));
        let b = e.c.get_batch(U64(0)).unwrap();
        assert_eq!(b.state, BatchState::Finalized);
        assert!(b.bids.iter().all(|x| x.settled));
        let calls = intents_calls();
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|c| c.contains("\"10\"") && c.contains("\"1000\"")), "{calls:?}");
        testing_env!(ctx("anyone.testnet", 0, 301).build());
        assert!(fails(|| e.c.refund(U64(0))));
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
        assert!(fails(|| { let _ = e.c.close_batch(U64(0)); }));
    }

    #[test]
    fn bid_cap_enforced() {
        let mut e = setup(2);
        bid(&mut e, "a.testnet", r#"{"side":"buy","price":"1","qty":"1"}"#);
        bid(&mut e, "b.testnet", r#"{"side":"buy","price":"1","qty":"1"}"#);
        let (ct, _) = seal(&mut e, "{}");
        testing_env!(ctx("c.testnet", BOND, 10).build());
        assert!(fails(|| e.c.submit_bid(U64(0), ct.clone())), "third bid must hit max_bids");
        assert!(fails(|| setup(MAX_BIDS_HARD_CAP + 1)));
    }

    #[test]
    fn full_lifecycle_settles_and_refunds_unused_escrow() {
        let mut e = setup(5);
        let ob = r#"{"side":"buy","price":"90","qty":"10"}"#;
        let os = r#"{"side":"sell","price":"80","qty":"6"}"#;
        let ox = r#"{"side":"buy","price":"101","qty":"5"}"#; // above max_price
        let ou = r#"{"side":"buy","price":"95","qty":"5"}"#; // never escrowed
        let (i0, s0) = bid(&mut e, "alice.testnet", ob);
        let (i1, s1) = bid(&mut e, "bob.testnet", os);
        let (i2, s2) = bid(&mut e, "carol.testnet", ox);
        let (i3, s3) = bid(&mut e, "dave.testnet", ou);
        escrow(&mut e, "alice.testnet", i0);
        escrow(&mut e, "bob.testnet", i1);
        escrow(&mut e, "carol.testnet", i2);
        close(&mut e);
        assert!(callback(&mut e, true));
        testing_env!(ctx("keeper.testnet", 0, 210).build());
        e.c.submit_opening(U64(0), i0, ob.into(), hex::encode(s0));
        e.c.submit_opening(U64(0), i1, os.into(), hex::encode(s1));
        assert!(fails(|| e.c.submit_opening(U64(0), i2, ox.into(), hex::encode(s2))), "over max_price");
        assert!(fails(|| e.c.submit_opening(U64(0), i3, ou.into(), hex::encode(s3))), "no escrow");
        testing_env!(ctx("keeper.testnet", 0, 400).build());
        // tie-break: volume 6 at every price in [80, 90] → lowest (80)
        assert_eq!(e.c.finalize(U64(0)), Some(U128(80)));
        let calls = intents_calls();
        // alice: 10+6 base, 1000-480 quote; bob: 10-6 base, 1000+480 quote; carol: bundle back; dave: nothing escrowed
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("alice") && c.contains("\"16\"") && c.contains("\"520\"")), "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("bob") && c.contains("\"4\"") && c.contains("\"1480\"")), "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("carol") && c.contains("\"10\"") && c.contains("\"1000\"")), "{calls:?}");
    }

    // ---------------- shielded pool tests ----------------
    const PB: &str = r#"{"side":"buy","price":"100","qty":"10"}"#;
    fn vectors() -> near_sdk::serde_json::Value {
        near_sdk::serde_json::from_str(include_str!("../tests/zk_vectors.json")).unwrap()
    }
    fn vs(v: &near_sdk::serde_json::Value, path: &[&str]) -> String {
        let mut x = v;
        for k in path { x = &x[*k]; }
        x.as_str().unwrap().to_string()
    }
    fn dec_to_le(d: &str) -> String {
        hex::encode(zk::fr_to_le(&<ark_bn254::Fr as std::str::FromStr>::from_str(d).ok().unwrap()))
    }
    fn pool_setup() -> (Env, near_sdk::serde_json::Value) {
        let e = setup(5);
        let mut e = e;
        testing_env!(ctx(ME, 0, 1).build());
        e.c.init_pool(PoolConfig { base_token: BASE.into(), quote_token: QUOTE.into(), max_qty: U128(MAXQ), max_price: U128(MAXP), bond: U128(BOND) });
        let v = vectors();
        for (i, who) in ["dep0.testnet", "dep1.testnet", "dep2.testnet"].iter().enumerate() {
            let c = v["leavesHex"][i].as_str().unwrap().to_string();
            testing_env!(ctx(who, BOND, 2).build());
            e.c.pool_deposit_bond(c.clone());
            testing_env!(ctx(INTENTS, 0, 3).build());
            let r = e.c.mt_on_transfer(acc(who), vec![acc(who), acc(who)], vec![BASE.into(), QUOTE.into()],
                vec![U128(MAXQ), U128(MAXQ * MAXP)], format!("{{\"deposit\":\"{c}\"}}"));
            assert_eq!(r, vec![U128(0), U128(0)]);
        }
        (e, v)
    }

    /// Prints the deterministic ciphertext used to generate tests/zk_vectors.json.
    #[test]
    #[ignore]
    fn dump_private_bid_ct() {
        let mut e = setup(5);
        println!("CT {}", seal(&mut e, PB).0);
    }

    #[test]
    fn poseidon_and_tree_match_circomlibjs() {
        let v = vectors();
        let h = zk::poseidon(&[ark_bn254::Fr::from(1u64), ark_bn254::Fr::from(2u64)]);
        assert_eq!(hex::encode(zk::fr_to_le(&h)), dec_to_le(v["h12"].as_str().unwrap()));
        let t = zk::Tree::new();
        assert_eq!(hex::encode(t.root()), dec_to_le(v["zeros"][16].as_str().unwrap()));
        let (e, v) = pool_setup();
        let info = e.c.pool_info();
        assert_eq!(info["root"].as_str().unwrap(), vs(&v, &["bid", "rootHex"]));
        assert_eq!(info["size"], 3);
    }

    #[test]
    fn pool_deposit_requires_bond_and_exact_bundle() {
        let (mut e, _) = pool_setup();
        let c = dec_to_le("12345");
        testing_env!(ctx("x.testnet", BOND - 1, 2).build());
        assert!(fails(|| e.c.pool_deposit_bond(c.clone())), "bond must be exact");
        testing_env!(ctx(INTENTS, 0, 3).build());
        assert!(fails(|| e.c.mt_on_transfer(acc("x.testnet"), vec![acc("x.testnet"), acc("x.testnet")], vec![BASE.into(), QUOTE.into()],
            vec![U128(MAXQ), U128(MAXQ * MAXP)], format!("{{\"deposit\":\"{c}\"}}"))), "tokens before bond");
        testing_env!(ctx("x.testnet", BOND, 2).build());
        e.c.pool_deposit_bond(c.clone());
        testing_env!(ctx(INTENTS, 0, 3).build());
        assert!(fails(|| e.c.mt_on_transfer(acc("x.testnet"), vec![acc("x.testnet"), acc("x.testnet")], vec![BASE.into(), QUOTE.into()],
            vec![U128(MAXQ), U128(999)], format!("{{\"deposit\":\"{c}\"}}"))), "wrong bundle");
        testing_env!(ctx("x.testnet", 0, 4).build());
        e.c.pool_cancel_bond(c.clone());
    }

    #[test]
    fn private_bid_verifies_binds_and_settles_to_fresh_payout() {
        let (mut e, v) = pool_setup();
        let (ct, sigma) = seal(&mut e, PB);
        let b = &v["bid"];
        let (proof, root, nh) = (vs(b, &["proofHex"]), vs(b, &["rootHex"]), vs(b, &["nhHex"]));
        let fee = U128(1000);
        // Tampering with any bound field breaks the proof.
        testing_env!(ctx("relayer.testnet", 0, 10).build());
        assert!(fails(|| e.c.submit_private_bid(U64(0), ct.clone(), proof.clone(), root.clone(), nh.clone(), acc("thief.testnet"), fee)), "payout swap");
        assert!(fails(|| e.c.submit_private_bid(U64(0), ct.clone(), proof.clone(), root.clone(), nh.clone(), acc("payout-fresh.testnet"), U128(2000))), "fee change");
        testing_env!(ctx("other-relayer.testnet", 0, 10).build());
        assert!(fails(|| e.c.submit_private_bid(U64(0), ct.clone(), proof.clone(), root.clone(), nh.clone(), acc("payout-fresh.testnet"), fee)), "relayer swap");
        testing_env!(ctx("relayer.testnet", 0, 10).build());
        let mut bad = hex::decode(&proof).unwrap(); bad[200] ^= 1;
        assert!(fails(|| e.c.submit_private_bid(U64(0), ct.clone(), hex::encode(&bad), root.clone(), nh.clone(), acc("payout-fresh.testnet"), fee)), "bad proof");
        let i = e.c.submit_private_bid(U64(0), ct.clone(), proof.clone(), root.clone(), nh.clone(), acc("payout-fresh.testnet"), fee);
        assert!(e.c.is_spent(nh.clone()));
        assert!(fails(|| e.c.submit_private_bid(U64(0), ct.clone(), proof.clone(), root.clone(), nh.clone(), acc("payout-fresh.testnet"), fee)), "double spend");
        let pb = e.c.get_batch(U64(0)).unwrap().bids[i as usize].clone();
        assert_eq!(pb.bidder.as_str(), "payout-fresh.testnet");
        assert_eq!((pb.escrow_base.0, pb.escrow_quote.0), (MAXQ, MAXQ * MAXP));
        // A transparent seller to trade against.
        let os = r#"{"side":"sell","price":"90","qty":"7"}"#;
        let (j, s1) = bid(&mut e, "seller.testnet", os);
        escrow(&mut e, "seller.testnet", j);
        close(&mut e);
        assert!(callback(&mut e, true));
        testing_env!(ctx("keeper.testnet", 0, 210).build());
        e.c.submit_opening(U64(0), i, PB.into(), hex::encode(sigma));
        e.c.submit_opening(U64(0), j, os.into(), hex::encode(s1));
        testing_env!(ctx("keeper.testnet", 0, 400).build());
        assert_eq!(e.c.finalize(U64(0)), Some(U128(90)));
        let calls = intents_calls();
        assert!(calls.iter().any(|c| c.contains("payout-fresh") && c.contains("\"17\"") && c.contains("\"370\"")), "{calls:?}");
        let near_to = |who: &str| near_sdk::test_utils::get_created_receipts().iter().filter(|r| r.receiver_id.as_str() == who)
            .flat_map(|r| r.actions.clone()).filter_map(|a| match a { near_sdk::mock::MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()), _ => None }).sum::<u128>();
        assert_eq!(near_to("relayer.testnet"), 1000);
        assert_eq!(near_to("payout-fresh.testnet"), BOND - 1000);
    }

    #[test]
    fn pool_withdraw_with_proof_and_no_reuse() {
        let (mut e, v) = pool_setup();
        let w = &v["withdraw"];
        let (proof, root, nh) = (vs(w, &["proofHex"]), vs(w, &["rootHex"]), vs(w, &["nhHex"]));
        testing_env!(ctx("relayer.testnet", 0, 10).build());
        assert!(fails(|| e.c.pool_withdraw(proof.clone(), root.clone(), nh.clone(), acc("thief.testnet"), U128(0))));
        e.c.pool_withdraw(proof.clone(), root.clone(), nh.clone(), acc("withdraw-fresh.testnet"), U128(0));
        let calls = intents_calls();
        assert!(calls.iter().any(|c| c.contains("withdraw-fresh") && c.contains("\"10\"") && c.contains("\"1000\"")), "{calls:?}");
        assert!(fails(|| e.c.pool_withdraw(proof.clone(), root.clone(), nh.clone(), acc("withdraw-fresh.testnet"), U128(0))), "reuse");
    }
}
