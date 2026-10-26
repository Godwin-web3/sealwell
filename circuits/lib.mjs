// Sealwell shielded-pool helpers: notes, Poseidon Merkle tree, proof generation and NEAR encoding.
import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { createHash, randomBytes } from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
const DIR = path.dirname(fileURLToPath(import.meta.url));
export const LEVELS = 16;
export const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
let _p; export async function poseidon() { if (!_p) _p = await buildPoseidon(); return (xs) => _p.F.toObject(_p(xs.map(BigInt))); }

export const toLE = (x, n = 32) => { x = BigInt(x); const b = Buffer.alloc(n); for (let i = 0; i < n; i++) { b[i] = Number(x & 255n); x >>= 8n; } return b; };
export const fromLE = (b) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
export const fieldHex = (x) => toLE(x).toString("hex");

export async function newNote() {
  const H = await poseidon();
  const rnd = () => fromLE(randomBytes(31));
  const nullifier = rnd(), secret = rnd();
  return { nullifier: nullifier.toString(), secret: secret.toString(), commitment: H([nullifier, secret]).toString(), nullifierHash: H([nullifier]).toString() };
}

export async function zeros() { const H = await poseidon(); const z = [0n]; for (let i = 0; i < LEVELS; i++) z.push(H([z[i], z[i]])); return z; }

// Rebuild the tree from the ordered leaf list (as read from the contract) and return a path for `index`.
export async function merklePath(leaves, index) {
  const H = await poseidon(); const z = await zeros();
  let layer = leaves.map(BigInt); const pathElements = [], pathIndices = [];
  for (let l = 0; l < LEVELS; l++) {
    const sib = index ^ 1; pathElements.push((sib < layer.length ? layer[sib] : z[l]).toString()); pathIndices.push(index & 1);
    const next = []; for (let i = 0; i < Math.ceil(layer.length / 2); i++) next.push(H([layer[2 * i], 2 * i + 1 < layer.length ? layer[2 * i + 1] : z[l]]));
    layer = next.length ? next : [z[l + 1]]; index >>= 1;
  }
  return { root: layer[0].toString(), pathElements, pathIndices };
}

// extHash: binds a proof to its action. Must match `ext_hash` in the contract.
// sha256(utf8 JSON of [action, batch_id, ct_sha256_hex, payout, relayer, fee]) as a big-endian integer, top 3 bits cleared (< 2^253 < r).
export function extHash({ action, batchId, ctHex = "", payout, relayer, fee }) {
  const ctH = ctHex ? createHash("sha256").update(Buffer.from(ctHex, "hex")).digest("hex") : "";
  const s = JSON.stringify([action, String(batchId), ctH, payout, relayer, String(fee)]);
  const d = createHash("sha256").update(s).digest(); d[0] &= 0x1f;
  return BigInt("0x" + d.toString("hex")).toString();
}

// NEAR alt_bn128 encodings: G1 = x‖y (32-byte LE each); G2 = x.c0‖x.c1‖y.c0‖y.c1.
export const g1 = (p) => Buffer.concat([toLE(p[0]), toLE(p[1])]);
export const g2 = (p) => Buffer.concat([toLE(p[0][0]), toLE(p[0][1]), toLE(p[1][0]), toLE(p[1][1])]);
export const encodeProof = (pr) => Buffer.concat([g1(pr.pi_a), g2(pr.pi_b), g1(pr.pi_c)]).toString("hex");

export async function prove(note, leaves, index, ext) {
  const { root, pathElements, pathIndices } = await merklePath(leaves, index);
  const input = { root, nullifierHash: note.nullifierHash, extHash: ext, nullifier: note.nullifier, secret: note.secret, pathElements, pathIndices };
  const t0 = Date.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, path.join(DIR, "build/spend_js/spend.wasm"), path.join(DIR, "build/spend.zkey"));
  const ms = Date.now() - t0;
  const vk = JSON.parse(fs.readFileSync(path.join(DIR, "build/verification_key.json")));
  if (!(await snarkjs.groth16.verify(vk, publicSignals, proof))) throw new Error("local verify failed");
  return { proofHex: encodeProof(proof), root, nullifierHash: note.nullifierHash, extHash: ext, ms, publicSignals };
}
