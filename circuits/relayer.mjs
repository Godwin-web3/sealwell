#!/usr/bin/env node
// Minimal relayer: submits a request produced by cli.mjs from the relayer's own NEAR account.
// The proof binds payout, relayer and fee, so a relayer can censor or delay but cannot redirect funds or raise its fee.
//   RELAYER_ACCOUNT=relayer.testnet RELAYER_KEY=ed25519:... node relayer.mjs <request.json>
// (key from the environment; never commit it). Testnet by default.
import fs from "fs"; import nearApi from "near-api-js";
export async function relay(req, accountId, secretKey, nodeUrl = process.env.NEAR_RPC || "https://rpc.testnet.fastnear.com") {
  if (req.relayer !== accountId) throw new Error(`request is bound to relayer ${req.relayer}, not ${accountId}`);
  const ks = new nearApi.keyStores.InMemoryKeyStore(); await ks.setKey("testnet", accountId, nearApi.KeyPair.fromString(secretKey));
  const near = await nearApi.connect({ networkId: "testnet", nodeUrl, keyStore: ks });
  const acct = await near.account(accountId);
  return acct.functionCall({ contractId: req.contract, methodName: req.method, args: req.args, gas: "250000000000000", attachedDeposit: "0" });
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const r = await relay(JSON.parse(fs.readFileSync(process.argv[2])), process.env.RELAYER_ACCOUNT, process.env.RELAYER_KEY);
  console.log(r.transaction.hash, JSON.stringify(r.status).slice(0, 200)); process.exit(0);
}
