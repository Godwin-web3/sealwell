# Testnet evidence

Everything here ran on NEAR **testnet** using throwaway accounts and testnet tokens. MPC contract: `v1.signer-prod.testnet` (v3.17.0), CKD domain 2.

## Contract: `sealwell-auction-v2-1793005100.testnet` (Oct 26, 2026, WAT)

The Wasm is 322 KB (built with `cargo near build non-reproducible-wasm --no-abi`).

| Step | Tx | Result |
|---|---|---|
| deploy | `8MtC2hA6oJ2zSKCWfv37bQQQZoB5eFTnWdmRuxPttTv3` | |
| init | `8FzozWDyMeFZiAN7SUErzE9g7JHs45ytmoCnoWo4L3gH` | |
| bench_hash_to_curve | `DU4TyNcv4YrJozF4irv4NDK3RLLaQAzmJn2zUgzARVNr` | Host and arkworks results are equal |
| open_batch(40 s, reveal 150 s, min bond 0.1 Ⓝ) | `FVYcf3WWtBxeFaWT1XbKwiK3C8LAeJJSrzesCYFnRy9z` | batch 0 |
| submit_bid #0: buy 100×10, bond 0.2 Ⓝ | `Saq5u2rGvXNjgBRjExZ8smRDvuuqbutEsHJVNnYqvib` | |
| submit_bid #1: sell 90×7 | `EW97LSZuTQbovVguBpC2QMVs5fmt5NM9j4hbtETPZGQm` | |
| submit_bid #2: buy 120×5 | `BFkQgRJi2U55NSgfhTB64GEQEKUHYeawWEB8DHjUSRbM` | |
| close_batch before deadline | — | reverted: `deadline not reached` |
| **close_batch → MPC CKD → on_ckd** | **`J8pCmEvbgucV9AVdxyiDm87vLDLV4ajGod5tiLYXp7EJ`** | MPC logged `predecessor=sealwell-auction-v2-1793005100.testnet, path sealwell/batch/0`. The key verified on-chain and the batch moved to `Revealed` |
| submit_opening #0 | `FupmcyW9ohhuKUs4C7SFi2AjXjT9QGwvvv4RoZnyohgk` | accepted |
| submit_opening #1 | `7gjiDLZbX15P64YSzmc7QbeQAoxQTUk5MC47f2PLoV9q` | accepted |
| submit_opening #2 with a false plaintext | (reverted) | `opening does not match ciphertext (U)` |
| finalize | `Cxw8kyr3X5xxcs8HkswjqLYVbuqK2fVZfSsynpNrmzMw` | Clearing price 90, qty 7 settled (`settle_mocked`). Bonds #0 and #1 were refunded; bond #2 was slashed to the treasury |

Released key details:
- `sk_b` = `8429de91…2f6be`
- app_id = `e44a14d9…ea030` = SHA3-256("near-mpc v0.1.0 app_id derivation:" ‖ contract ‖ "," ‖ "sealwell/batch/0")
- An off-chain keeper decrypted bid #0 with it: `seal --open … → {"side":"buy","price":"100","qty":"10"}`

## Gas (from contract logs)

| Operation | Gas |
|---|---|
| hash_to_curve G1, arkworks in Wasm | **24.9 Tgas** |
| hash_to_curve G1, host (`map_fp_to_g1` + `p1_sum`, XMD in Wasm) | **1.19 Tgas** |
| CKD unwrap C − a·Y: arkworks (v1 deploy) / host `g1_multiexp` | 38.8 / **2.5 Tgas** |
| `bls12381_pairing_check` (2 pairs, key verification) | **6.5 Tgas** |
| close_batch before the promise (a, pk1, pk2): arkworks (v1) / host | 79.9 / **4.1 Tgas** |
| MPC `request_app_private_key` receipts | 11.7 + 3.8 Tgas |
| on_ckd callback total | 12.4 Tgas |
| Opening check by full re-encryption, arkworks in Wasm (v1 deploy) | **> 300 Tgas, fails** (`Exceeded the prepaid gas`) |
| Opening check, U via host `g2_multiexp` | 2.4 Tgas |
| Opening check, one in-Wasm pairing + mask + AEAD | **119.8 Tgas** (124 Tgas total receipt) |
| submit_bid / finalize (3 bids) | 21 / 2.6 Tgas |

The first deploy, `auction-v1.sealwell-probe-1793003413.testnet` (close tx `759uEh8xQKAQoMuPuiHGThQCNYV2iku4grY5XktWoHVp`), did all of its arithmetic in arkworks. Its CKD key release still worked, but opening verification ran out of gas. v2 moved the arithmetic to host functions. The one remaining in-Wasm pairing exists because the host only exposes a boolean pairing check, while the IBE mask needs the GT element itself.

## v3: Intents escrow + settlement, hardening, forced MPC failure (Oct 26, 2026)

**Which verifier:** NEAR Intents has no testnet deployment, so the verifier is **self-deployed**:
`intents.sealwell-probe-1793003413.testnet`, built from `near/intents` @ `d340060` (`defuse` 0.4.5), init
`new({config:{wnear_id:"wrap.testnet", fees:{fee:0, fee_collector:<probe>}, roles:{super_admins:[<probe>]}}})`.
It is **not** `intents.near`. Test tokens: `base.` and `quote.sealwell-probe-1793003413.testnet` (the repo's `releases/fungible-token.wasm`).

| Step | Tx | Notes |
|---|---|---|
| create / deploy / init verifier | `7XRLMUbjiC5a5msUFzasPybntupg2hAFNfURVzi8yh2Z` / `3KrHv8MnvpouJYQjJjZeqdNGTAEA1tosb7YuK93e1LEa` / `D4sWk9aLPraVtpnHKPq2VqBBPoNjfthDrQEhnkAD1Rhh` | 1.29 MB wasm |
| base / quote token init | `C5SSKy2NHBPpQRzuCCcQRngSFxDBPnBH6JhxP6757zCC` / `AQE6q8BeQ4DPzKeh3nupHHEECbKNhipPbP8hFsYimGLc` | |
| auction v3 deploy / init | `EvnozCsrLQGshCLZAGqrEcsi2vXKDAkHuUAA6yJ19qRN` / `5spEAQ2bpFedEG2saUBbe1XDMLmUoN57iSRyhwssjFwb` | `sealwell-auction-v3-3005975.testnet` |
| bidder0 deposit to verifier (`ft_transfer_call`) | `8SXTRCsY3hBjsp9LLQztZTgs3SsRVE7vje1jnMCJypBx` | 1000 quote, 8.4 Tgas total |
| open_batch (max_bids 5) | `9cBjAedRCN8R5Wo2tuaCDFs4TaDZARk3KhBdPYbtdz4y` | |
| submit_bid ×3 | `9GGtVLaob9zk6taJohmEcsmhxCB9veRdsQYRrTcXc1E2`, `BfP1Neuf6RhPouAiPGAnDtn49EHhbfhK4rgehLQCWbwT`, `H5F81Ey1BoAByidNfNUzqMLb8cvsrHJvTsK5BCpLyjj7` | **~2.0 Tgas** in the contract (was ~21 Tgas with the arkworks decode; now a length check + host `p2_decompress`) |
| escrow `mt_transfer_call` ×3 | `BW3RyT5P3aNE6RXAAD6xxCgVZgFCbZYHtA3V7jfRe8Wi`, `9HjB7y7KgqunBMFuBV5As3DGGnP4QWuyHdjNui3XqiYx`, `3XjN73zed5JUiZ6YEDJp84GSKEbb6wXcXynyTT1kb9dq` | 1000 quote / 7 base / 600 quote; ~10.5 Tgas each, `mt_on_transfer` ~1.8 Tgas |
| close_batch → CKD → on_ckd | `oWBq7yVpgsXJ9JsdEj9jQ76Mbzc1V72ZGLmoevek1gr` | state `Revealed` |
| submit_opening ×2 | `5GUajP8tCLaYwgs2bnqeaJ8h8Bq3BoHzUsB5drZujH6w`, `J6df7ERQdXZy1Z4ch3kjjgTgqfrbnmW6T2rv9av45XGo` | ~124 Tgas each (unchanged) |
| **finalize** | `Dk11k5swkAMudhUdY7xELEA7gCSc8Rek3oRWDr8tPNVy` | price 90, volume 7; auction 3.8 Tgas + three verifier `mt_batch_transfer` receipts 4.8 / 3.8 / 4.0 Tgas |

Orders: buy 100×10 (escrow 1000 quote), sell 90×7 (escrow 7 base), buy 120×5 (escrow 600 quote, never opened).
Verifier balances after `finalize` (`mt_batch_balance_of`, [base, quote]): seller `[0, 630]`, unopened bidder `[0, 600]` (escrow returned, 0.2 NEAR bond slashed to treasury), auction `[0, 0]`.
Buyer `[7, 1370]` = 7 base + 370 quote change from this batch + 1000 quote refunded from the failure run below (same test account).
Tie-break shown live: volume 7 at every price in [90, 100], so the lowest (90) was picked.

**Forced MPC failure → refund** on `sealwell-auction-v3f-3005975.testnet` (deploy `5oG1kGXMvT3yRN7xJKJgUmvx1Nhh7884m2Kvz42JdmUG`, init `VGkzVmeaj2vszPBLDVYyUA8qevwcGko6mbLezrJ8ruv`, initialised with **domain_id 0** on purpose):

| Step | Tx | Notes |
|---|---|---|
| close_batch | `J4xXqGcPpFY9bqH8dzCcQoPtgGgSaLCbZy8nmoBRzMzx` | MPC receipt failed: `Domain 0 has purpose Sign, but this method requires CKD.`; `on_ckd` returned `false` (2.0 Tgas) → `Failed` |
| refund (called by the bidder) | `6YMzBJk4ts9sBrcvp6pvUhtRqMmtFbXLSoaRJ4dK5RZ7` | 0.2 NEAR bond + 1000 quote escrow returned (`mt_transfer` from auction → bidder); auction verifier balance 0 |

Raw gas reports: [`docs/logs/v3-settlement-run.json`](logs/v3-settlement-run.json), [`docs/logs/v3-mpc-failure-refund-run.json`](logs/v3-mpc-failure-refund-run.json).

**Not shown live:** a timeout (as opposed to an error) from the MPC, and a `close_batch` retry after failure (both are covered by unit tests only).

## v4: side- and size-blind escrow (Oct 26, 2026, WAT)

Contract `sealwell-auction-v4-3006944.testnet` (deploy `DqSxG5ybkvJ3DBLrPXMbSD8ExnKhZeN6cYxAt1oSAoYE`, init `GabnzmrWimidm14q8jQwBzXsyR6p7JvdDwFa5xhbfAWS`, CKD domain 2). Verifier: `intents.sealwell-probe-1793003413.testnet` (self-deployed near/intents). Batch 0: `max_qty = 10`, `max_price = 100`, bond 0.1 NEAR, so the bundle is `{10 base, 1000 quote}`.

| Step | Buyer `sw-bidder0` (buy 10 @ 100) | Seller `sw-bidder1` (sell 7 @ 90) |
|---|---|---|
| submit_bid (208-byte ct, 0.1 NEAR) | `5juegev2XACJ5TLHVpcEQFPqdsNbvY9spbg7pVCsZeXD`, 2.03 Tgas | `5yVwd66N5ygq2XFRrMWYmnDozpg79vWxcThcysfYR3TV`, 2.06 Tgas |
| escrow `mt_batch_transfer_call` `[base, quote]` / `["10","1000"]` | `9twLgtFrLkZGFNhkPLYzwQZmFaEwixrNcujSTsXXiAkD` | `FkR6XaqVnqmra5r8o5rkDF7Vf4QJCsahseqG6zaHRv3J` |
| submit_opening | `HzetcU1eGkyz5dVgzjxCT71vMwWiBretFmKhFa7KyD1a`, 124.0 Tgas | `DYr6V4CvgDgbgt6KcqZXLTqz9s1vvRjdbAppSXozDwTP`, 124.0 Tgas |

The two escrow txs carry the same tokens, amounts, deposit (1 yocto) and gas burnt (0.32 Tgas for the tx). The only difference is `bid_index` in `msg`. On-chain escrow after both calls: `[[bidder0,"10","1000"],[bidder1,"10","1000"]]`.

- open_batch `349HDkKAevbnb9W21fhMXWJTfAp9QuBw73iHMDZzJMUQ`
- close_batch `39MYYoibdMR8Wt2iTC8TufJ8A87uEw18Sm4wH2sHwVgr`: CKD key released, then `Revealed`
- finalize `FXKMx6779e21X2N9YtnmzbdDeqRGD8d5n6X6ap2bYrqK`: clearing price 90, volume 7
  - buyer receives 17 base + 370 quote (7 fill + 10 unused base; 1000 − 630)
  - seller receives 3 base + 1630 quote (10 − 7; 1000 + 630)

Verifier balances (base, quote):

| Account | Before batch | After finalize |
|---|---|---|
| buyer | 17, 2370 | 24, 1740 |
| seller | 10, 630 | 3, 2260 |
| auction | — | 0, 0 |

Net: buyer +7 base, −630 quote; seller −7 base, +630 quote. All unused escrow was returned. Raw log: [`logs/e2e4-log.json`](logs/e2e4-log.json).
