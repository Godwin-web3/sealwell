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
4. **Verify & decrypt.** Anyone checks the key with one pairing equation, decrypts all bids, and submits openings. Openings are checked deterministically (Fujisaki–Okamoto re-encryption), so garbage ciphertexts are provably invalid and their bonds can be slashed.
5. **Clear & settle.** One uniform clearing price; winning fills settle through `intents.near`.

Key-release is gated by **contract logic**, not a clock or a separate committee, and reuses NEAR's existing MPC trust set (11-of-N, nodes in Intel TDX).

Crypto details: [`docs/crypto.md`](docs/crypto.md).

## Status

| Component | State |
|---|---|
| `crates/sealwell-ibe` — app_id, RFC 9380 hash-to-G1, BF-IBE + FO (CCA), key verification, CKD unwrap, public opening check, wasm build | ✅ Done, tested (11 tests incl. real testnet vectors) |
| `contracts/sealwell-auction` — batch lifecycle, CKD call via yield/resume, bonds, clearing, Intents settlement | ⏳ Not started (stub) |
| `cli/` — bidder & keeper | ⏳ Not started (stub) |
| Web demo | ⏳ Not started |

## Live testnet proof

A CKD call against `v1.signer-prod.testnet` (contract v3.17.0, domain 2 `ConfidentialKeyDerivation`, threshold 11):

- tx **`C1WHYDd99EhBrBQLujiKqyY5SSnDhrzaigNJduLXwoRP`** and repeat **`HM49W4zbwtDzWUvyogidh86NMLhZQW2gAPLdd7eCXPx7`** (caller `sealwell-probe-1793003413.testnet`, path `sealwell-batch-0`)
- Both returned ElGamal-wrapped outputs that unwrap to the **same** key, which verifies `e(key, G2) = e(H(mpk, app_id), mpk)`.
- [`tests/testnet_vectors.rs`](crates/sealwell-ibe/tests/testnet_vectors.rs) reproduces this in Rust from public values only, and encrypts-to-identity → decrypts with the released key.

Note: these calls were made from a plain account. Calling CKD **from a contract** (the actual design) is the next milestone.

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
- **Liveness:** depends on the MPC answering; batches time out and refund otherwise.
- **Metadata:** bidder accounts and ciphertext sizes leak (pad messages).
- **Contract upgrades:** an upgradable owner could request a key early — deploy locked or behind a timelock.
- **MPC key rotation:** resharing keeps `mpk`; a new CKD domain would orphan in-flight ciphertexts.

## License

MIT OR Apache-2.0.
