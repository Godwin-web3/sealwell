# Cryptography

Notation: BLS12-381, `G1`, `G2` generators, `e` the pairing. NEAR MPC CKD domain holds `msk`; `mpk = msk·G2`.

* `app_id = SHA3-256("near-mpc v0.1.0 app_id derivation:" ‖ predecessor ‖ "," ‖ path)` — `predecessor` is the account (or contract) that called the MPC contract.
* `H = hash_to_curve_G1(compress(mpk) ‖ app_id)`, RFC 9380 `XMD:SHA-256_SSWU_RO_`, DST `NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_`.
* CKD returns `(Y, C)` ElGamal-encrypted to the caller's `A = a·G1`; `sk_id = C − a·Y = msk·H`.
* Key check: `e(sk_id, G2) = e(H, mpk)`.

Encryption (Boneh–Franklin FullIdent, Fujisaki–Okamoto):

```
σ ← random 32 bytes
r = H3(app_id, σ, M)          (wide SHA-256 → Fr)
U = r·G2
V = σ ⊕ H2(U, e(H, mpk)^r)
W = ChaCha20-Poly1305_{H4(σ)}(M; aad = U ‖ V ‖ app_id), nonce 0 (key is single-use)
```

Decrypt: `g = e(sk_id, U)`, `σ = V ⊕ H2(U, g)`, open `W`, recompute `r`, reject unless `r·G2 = U`.

`verify_opening(ct, M, σ)` re-encrypts deterministically — anyone can check a published plaintext without the key.
