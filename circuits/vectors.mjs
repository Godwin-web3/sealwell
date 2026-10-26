// Test vectors for the Rust unit tests: 3 notes in a tree, a bid proof for note 1, a withdraw proof for note 2.
import fs from "fs"; import * as L from "./lib.mjs";
const notes = [await L.newNote(), await L.newNote(), await L.newNote()];
const leaves = notes.map((n) => n.commitment);
const bidExt = { action: "bid", batchId: 0, ctHex: process.argv[2], payout: "payout-fresh.testnet", relayer: "relayer.testnet", fee: "1000" };
const bid = await L.prove(notes[1], leaves, 1, L.extHash(bidExt));
const wExt = { action: "withdraw", batchId: 0, payout: "withdraw-fresh.testnet", relayer: "relayer.testnet", fee: "0" };
const w = await L.prove(notes[2], leaves, 2, L.extHash(wExt));
const z = await L.zeros(); const H = await L.poseidon();
fs.writeFileSync(process.argv[3], JSON.stringify({ leaves, leavesHex: leaves.map(L.fieldHex), zeros: z.map(String), h12: H([1n, 2n]).toString(), bid: { ...bid, ext: bidExt, rootHex: L.fieldHex(bid.root), nhHex: L.fieldHex(bid.nullifierHash) }, withdraw: { ...w, ext: wExt, rootHex: L.fieldHex(w.root), nhHex: L.fieldHex(w.nullifierHash) } }, null, 1));
console.log("prove ms", bid.ms, w.ms, "extHash", bid.extHash);
process.exit(0);
