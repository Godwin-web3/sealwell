#!/usr/bin/env bash
# HACKATHON-ONLY trusted setup: local Powers of Tau + single-party phase 2.
# Whoever runs this knows the toxic waste unless entropy is discarded. NOT for production.
set -euo pipefail
cd "$(dirname "$0")"
circom spend.circom --r1cs --wasm -o build
S="npx snarkjs"
$S powersoftau new bn128 13 build/pot_0.ptau
$S powersoftau contribute build/pot_0.ptau build/pot_1.ptau --name="sealwell-local-1" -e="$(od -An -tx1 -N64 /dev/urandom | tr -d " \n")"
$S powersoftau beacon build/pot_1.ptau build/pot_b.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 10 -n="beacon"
$S powersoftau prepare phase2 build/pot_b.ptau build/pot_final.ptau
$S groth16 setup build/spend.r1cs build/pot_final.ptau build/spend_0.zkey
$S zkey contribute build/spend_0.zkey build/spend.zkey --name="sealwell-phase2-1" -e="$(od -An -tx1 -N64 /dev/urandom | tr -d " \n")"
$S zkey export verificationkey build/spend.zkey build/verification_key.json
$S zkey verify build/spend.r1cs build/pot_final.ptau build/spend.zkey
rm -f build/pot_0.ptau build/pot_1.ptau build/pot_b.ptau build/spend_0.zkey
