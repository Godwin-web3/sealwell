# Sealwell

**Sealed-bid batch auctions for NEAR Intents. Solver quotes stay unreadable until the auction contract closes the batch, and are then unlocked by NEAR's MPC network (Confidential Key Derivation).**

> ⚠️ Research prototype. **Testnet only. Unaudited.** Do not use with real funds.

## Problem

On NEAR Intents, solver quotes travel in the clear. Whoever sees them first — the relay, other solvers — can copy, shade, or last-look them. Common fixes have gaps:

- **Commit–reveal** lets a bidder refuse to reveal after seeing others (a free option).
- **Trusted sequencers / TEE-only private forks** move trust to an operator who may see plaintext.

## How it works

1. **Open.** The auction contract opens batch `b`. Its identity is fixed by NEAR MPC's CKD rule:
   `app_id = SHA3-256("near-mpc v0.1.0 app_id derivation:" ‖ contract_account ‖ "," ‖ "batch/b")`.
   Only that contract can ever request this identity's key.
2. **Bid.** Solvers encrypt quotes to that identity with Boneh–Franklin IBE using the MPC's public key `mpk` (CKD domain 2). No key exists yet; nobody — including the MPC nodes individually — can read bids.
3. **Close.** After the deadline the contract calls `request_app_private_key` on the MPC contract with a **public** scalar, so the returned identity key becomes public on purpose.
4. **Verify & decrypt.** Anyone checks the key with one pairing equation, decrypts all bids, and submits openings. Openings are checked deterministically on-chain (the Fujisaki–Okamoto check: `U = H3(σ,M)·G2` via a host multiexp, plus `V ⊕ H2(e(sk_b,U)) = σ` and the AEAD tag). Anyone (not only the bidder) can submit an opening, so a well-formed bid cannot be withheld, and a malformed one can't be opened by anyone and its bond is slashed.
5. **Escrow (side- and size-blind).** Each batch is opened with public limits `max_qty`, `max_price` and an exact NEAR `bond`. Every bid — buy or sell, big or small — attaches exactly `bond` and escrows exactly one bundle `{max_qty base, max_qty·max_price quote}` in a single `mt_batch_transfer_call(receiver = auction, msg = {batch_id, bid_index})` on the NEAR Intents verifier. Any other amount, a single token, or a second deposit is rejected. Order plaintexts are padded to 64 bytes, so every ciphertext is exactly 208 bytes. Before close, all bids look the same on-chain. An opening is valid only if the bid escrowed the bundle and `qty ≤ max_qty`, `price ≤ max_price`.
6. **Clear & settle.** One uniform clearing price. `finalize` pays every bid its fill plus all unused escrow with `mt_batch_transfer` on the verifier's ledger. Unopened bids get their escrow back but lose their NEAR bond.
   **Tie-breaking:** the price that maximises matched volume; if several prices tie, the **lowest** one. Within a side, fills go by price priority (best price first), then by bid index (earlier submission first).

Key-release is gated by **contract logic**, not a clock or a separate committee, and reuses NEAR's existing MPC trust set (11-of-N, nodes in Intel TDX).

Crypto details: [`docs/crypto.md`](docs/crypto.md).

## Status

| Component | State |
|---|---|
| `crates/sealwell-ibe` — app_id, RFC 9380 hash-to-G1, BF-IBE + FO (CCA), key verification, CKD unwrap, public opening check, wasm build | ✅ Done, tested (13 tests incl. real testnet vectors and constant ciphertext length) |
| `contracts/sealwell-auction` — batch lifecycle, CKD call from the contract + on-chain key verification, NEAR bonds, on-chain opening check, slashing, uniform-price clearing (one pair), bid cap, cheap ciphertext format check, CKD retry (max 3) and refund on MPC failure | ✅ Works on testnet (runs below), 12 unit tests incl. a full mocked lifecycle, a simulated CKD failure → refund, and a check that buyer and seller deposits are byte-identical |
| Escrow + settlement through a NEAR Intents verifier (NEP-245 `mt_batch_transfer_call` fixed bundle / `mt_batch_transfer`) | ✅ Live on testnet against a **self-deployed** verifier (see below). Not run against `intents.near` (mainnet only) |
| MPC failure → refund | ✅ Forced live (instance configured with a non-CKD domain): MPC call failed, batch `Failed`, bonds + escrow refunded |
| `cli/` — bidder & keeper | 🟡 Minimal: `cargo run -p sealwell-ibe --example seal` (seal a bid, keeper-decrypt with the released key) |
| Web demo | ⏳ Not started |

## Live testnet proof

A CKD call against `v1.signer-prod.testnet` (contract v3.17.0, domain 2 `ConfidentialKeyDerivation`, threshold 11):

- tx **`C1WHYDd99EhBrBQLujiKqyY5SSnDhrzaigNJduLXwoRP`** and repeat **`HM49W4zbwtDzWUvyogidh86NMLhZQW2gAPLdd7eCXPx7`** (caller `sealwell-probe-1793003413.testnet`, path `sealwell-batch-0`)
- Both returned ElGamal-wrapped outputs that unwrap to the **same** key, which verifies `e(key, G2) = e(H(mpk, app_id), mpk)`.
- [`tests/testnet_vectors.rs`](crates/sealwell-ibe/tests/testnet_vectors.rs) reproduces this in Rust from public values only, and encrypts-to-identity → decrypts with the released key.

### From the contract (Oct 26, 2026)

`sealwell-auction-v2-1793005100.testnet` called CKD from contract code, verified the key on-chain with `bls12381_pairing_check`, and ran a full 3-bid batch (2 opened, 1 bad opening rejected → slashed, clearing price 90). The `app_id` the MPC used is the contract's own (`derive_app_id(contract, "sealwell/batch/0")`), and the keeper decrypted a bid off-chain with the released key. All tx hashes and gas numbers: [`docs/testnet-evidence.md`](docs/testnet-evidence.md).

### Settlement through a NEAR Intents verifier (Oct 26, 2026)

NEAR Intents has **no testnet deployment** (the Verifier runs only as `intents.near` on mainnet). So this run uses a verifier we deployed ourselves: **`intents.sealwell-probe-1793003413.testnet`**, built from [near/intents](https://github.com/near/intents) at commit `d340060` (`defuse` v0.4.5, `cargo near build non-reproducible-wasm --locked --features=contract`). It is not the official deployment, and it uses our own test tokens `base.` / `quote.sealwell-probe-1793003413.testnet`.

On `sealwell-auction-v3-3005975.testnet`, three bidders deposited test tokens into the verifier, escrowed them to the auction, the CKD key was released, two bids were opened, and `finalize` (`Dk11k5swkAMudhUdY7xELEA7gCSc8Rek3oRWDr8tPNVy`) settled at price 90 with three `mt_transfer`s inside the verifier: buyer +7 base & 370 quote change, seller +630 quote, and the unopened bidder's 600 quote returned (its bond slashed). The auction's verifier balance ended at 0.

A second instance, `sealwell-auction-v3f-3005975.testnet`, was deliberately initialised with domain 0 (a signing domain). Its CKD call failed in the MPC contract (`Domain 0 has purpose Sign, but this method requires CKD.`), the callback set the batch to `Failed`, and `refund` (`6YMzBJk4ts9sBrcvp6pvUhtRqMmtFbXLSoaRJ4dK5RZ7`) returned the bond and the 1000-quote escrow. 

v4, `sealwell-auction-v4-3006944.testnet`, adds the uniform escrow. A buyer (buy 10 @ 100) and a seller (sell 7 @ 90) each sent a 208-byte ciphertext, a 0.1 NEAR bond, and the same `{10 base, 1000 quote}` bundle (`9twLgtFr…`, `FkR6XaqV…`; same arguments apart from `bid_index`, same gas burnt). `finalize` (`FXKMx6779e21X2N9YtnmzbdDeqRGD8d5n6X6ap2bYrqK`) cleared 7 @ 90 and paid back fills plus unused escrow: buyer 17 base + 370 quote, seller 3 base + 1630 quote. The auction ended holding 0. Details: [`docs/testnet-evidence.md`](docs/testnet-evidence.md).

```bash
cargo test                                                         # all tests
cargo build -p sealwell-ibe --target wasm32-unknown-unknown --features wasm --release
```

## Prior art (and what's different)

Sealwell combines well-known building blocks; we claim no new primitive.

- **Boneh–Franklin IBE** — D. Boneh, M. Franklin, *Identity-Based Encryption from the Weil Pairing*, CRYPTO 2001. The scheme used here (FullIdent / FO).
- **tlock / drand** — Gailly, Melissaris, Romailler, *tlock: Practical Timelock Encryption from Threshold BLS*, IACR ePrint 2023/189. Same idea keyed to time rounds.
- **Shutter Network** — threshold IBE by a keyper committee to prevent front-running (shutter.network).
- **ICP vetKeys** — Campanelli et al., *vetKeys*, IACR ePrint 2023/616. Verifiably encrypted threshold key derivation; same family as NEAR CKD.
- **NEAR CKD** — Near One, *Confidential Key Derivation* (blog.nearone.org, Feb 2026) and `near/mpc`. The primitive we consume.
- **Non-inclusion privacy** — IACR ePrint 2025/2048: a released identity key also decrypts ciphertexts that were never included. Applies to Sealwell (see below).
- **Frequent batch auctions** — Budish, Cramton, Shim, *The High-Frequency Trading Arms Race*, QJE 2015. Uniform-price batching; also CoW Protocol, Penumbra.

Sealwell's contribution: release gated by a NEAR contract's own state; applied to Intents solver quotes; no new committee; slashable invalid bids via public FO openings; explicit treatment of the non-inclusion leak.

## Threat model (summary)

- **Confidentiality before close:** holds unless ≥ threshold (11) MPC operators collude **and** defeat their TDX enclaves.
- **After close:** everything in the batch is public by design.
- **Non-inclusion leak:** a bid encrypted to batch `b` but censored/excluded is still decryptable once `b`'s key is out. Planned mitigation: per-bid identities `batch‖H(ct)`, requesting keys only for included bids (costs one CKD call per bid).
- **Liveness:** depends on the MPC answering. If the CKD call fails or times out, the batch becomes `Failed`; anyone may retry `close_batch` (up to 3 attempts) or call `refund` (bonds + escrow back).
- **Escrow (fixed):** every bid escrows the same bundle (`max_qty` base + `max_qty·max_price` quote) in one call, attaches the same bond, and carries a 208-byte ciphertext. So a pre-close observer can't tell side or size; the only bound is the public batch limit. Options considered:
  - (a) A fixed both-sides bundle (**chosen**). It's simple, has no extra leak, and costs capital: each bidder locks the worst case on both sides until `finalize`.
  - (b) Size tiers would lock less capital but reveal the tier, and a bidder would need to post both tokens per tier anyway to hide the side.
  - (c) Pooled or shielded escrow (commitments plus ZK range or solvency proofs, or a shielded pool) hides even participation amounts. It needs a proof system and a verifier on NEAR, so it's too heavy for now.
- **Still leaks:**
  - Who participates (bidder accounts are public).
  - How many bids there are.
  - The timing and order of bids and deposits.
  - The batch limits themselves.
  - Gas use, which is near-identical.
  - Each bidder's verifier balance history outside the auction (fund from fresh or shared accounts to blur it).
  - Everything after close.
- **Bid cap:** at most `max_bids` per batch (≤ 12) so `finalize` stays within one transaction's gas.
- **Contract upgrades:** an upgradable owner could request a key early — deploy locked or behind a timelock.
- **MPC key rotation:** resharing keeps `mpk`; a new CKD domain would orphan in-flight ciphertexts.

## License

MIT OR Apache-2.0.
