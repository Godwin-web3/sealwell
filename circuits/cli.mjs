#!/usr/bin/env node
// Sealwell shielded-pool CLI (client side, no keys). Keep note files OUTSIDE the repo: whoever holds a note can spend it.
//   node cli.mjs note <note.json>                                   create a fresh note
//   node cli.mjs bid-request <note.json> <contract> <batch> <ctHex> <payout> <relayer> <feeYocto> <out.json>
//   node cli.mjs withdraw-request <note.json> <contract> <recipient> <relayer> <feeYocto> <out.json>
// A request JSON is handed to a relayer (relayer.mjs), which submits it from its own account.
import fs from "fs"; import * as L from "./lib.mjs";
const RPC = process.env.NEAR_RPC || "https://rpc.testnet.fastnear.com";
export async function view(contract, method, args = {}) {
  const r = await fetch(RPC, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query",
    params: { request_type: "call_function", finality: "final", account_id: contract, method_name: method, args_base64: Buffer.from(JSON.stringify(args)).toString("base64") } }) }).then((r) => r.json());
  if (r.error || r.result?.error) throw new Error(JSON.stringify(r.error || r.result.error));
  return JSON.parse(Buffer.from(r.result.result).toString());
}
async function locate(note, contract) {
  const info = await view(contract, "pool_info");
  const leaves = info.leaves.map((h) => L.fromLE(Buffer.from(h, "hex")).toString());
  const index = leaves.indexOf(note.commitment);
  if (index < 0) throw new Error("note commitment not in pool (deposit not finished?)");
  if (await view(contract, "is_spent", { nullifier_hash_hex: L.fieldHex(note.nullifierHash) })) throw new Error("note already spent");
  return { leaves, index, info };
}
export async function bidRequest(note, contract, batch, ctHex, payout, relayer, fee) {
  const { leaves, index } = await locate(note, contract);
  const p = await L.prove(note, leaves, index, L.extHash({ action: "bid", batchId: Number(batch), ctHex, payout, relayer, fee: String(fee) }));
  return { contract, relayer, method: "submit_private_bid", prove_ms: p.ms, args: { batch_id: String(batch), ciphertext_hex: ctHex, proof_hex: p.proofHex,
    root_hex: L.fieldHex(p.root), nullifier_hash_hex: L.fieldHex(p.nullifierHash), payout, fee: String(fee) } };
}
export async function withdrawRequest(note, contract, recipient, relayer, fee) {
  const { leaves, index } = await locate(note, contract);
  const p = await L.prove(note, leaves, index, L.extHash({ action: "withdraw", batchId: 0, payout: recipient, relayer, fee: String(fee) }));
  return { contract, relayer, method: "pool_withdraw", prove_ms: p.ms, args: { proof_hex: p.proofHex, root_hex: L.fieldHex(p.root),
    nullifier_hash_hex: L.fieldHex(p.nullifierHash), recipient, fee: String(fee) } };
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const [cmd, ...a] = process.argv.slice(2); const rd = (f) => JSON.parse(fs.readFileSync(f));
  let out;
  if (cmd === "note") { const n = await L.newNote(); fs.writeFileSync(a[0], JSON.stringify(n), { mode: 0o600 }); console.log("commitment_hex", L.fieldHex(n.commitment)); }
  else if (cmd === "bid-request") { out = await bidRequest(rd(a[0]), ...a.slice(1, 7)); fs.writeFileSync(a[7], JSON.stringify(out, null, 1)); }
  else if (cmd === "withdraw-request") { out = await withdrawRequest(rd(a[0]), ...a.slice(1, 5)); fs.writeFileSync(a[5], JSON.stringify(out, null, 1)); }
  else { console.error("usage: see header"); process.exit(2); }
  if (out) console.log(out.method, "proof ms", out.prove_ms);
  process.exit(0);
}
