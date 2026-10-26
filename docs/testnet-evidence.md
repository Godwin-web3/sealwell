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
