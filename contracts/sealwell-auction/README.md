# sealwell-auction (stub — not implemented yet)
Planned NEAR contract: open batch → accept IBE ciphertexts + bonds → on close, call
`v1.signer-prod.testnet::request_app_private_key` (domain 2, `AppPublicKeyPV` with a public scalar)
via yield/resume → verify the key by pairing → accept keeper-submitted openings
(`verify_opening`) → uniform clearing price → settle via `intents.near`.
