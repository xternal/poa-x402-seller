#!/usr/bin/env node
// pay.mjs — pay a POA x402 seller from your own machine. One file; only needs `npm i viem`.
//
//   node pay.mjs --keygen                          # make a fresh key; get its address funded
//   node pay.mjs --quote                           # see what the seller asks (no key, no money)
//   PAYER_PRIVATE_KEY=0x… node pay.mjs             # pay once: notarize a random hash
//   PAYER_PRIVATE_KEY=0x… node pay.mjs --hash 0x<64 hex> [--max 0.01] [--url https://…/notarize]
//
// It refuses to sign anything it can't price honestly: the quote must be native USDC through
// POA's precompile 0x2d…0006 on chain 77, EIP-712 domain USDC/2, and 6-decimal amounts — never
// trust a seller's own `decimals` (a quote claiming 7 would make 0.5 USDC look like 0.05). And
// it never pays more than --max (default 0.01 USDC) per call.

import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { bytesToHex, formatUnits } from 'viem';
import { randomBytes } from 'node:crypto';

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const has = (k) => process.argv.includes(k);
const BASE = arg('--url', 'https://poa-x402-seller.fly.dev/notarize');
const HASH = arg('--hash', bytesToHex(randomBytes(32)));
const MAX = Number(arg('--max', '0.01'));
const RPC = 'https://rpc.poa.net';
const URL_ = `${BASE}${BASE.includes('?') ? '&' : '?'}hash=${HASH}`;
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const unb64 = (h) => { try { return JSON.parse(Buffer.from(h, 'base64').toString()); } catch { return null; } };

if (has('--keygen')) {
  const pk = generatePrivateKey();
  console.log(`address  ${privateKeyToAccount(pk).address}\nkey      ${pk}\n\nKeep the key secret. Send the ADDRESS to whoever is funding you (a few cents of POA USDC is plenty).`);
  process.exit(0);
}

// 1. Ask without paying.
const r1 = await fetch(URL_);
if (r1.status !== 402) { console.log(`expected 402, got ${r1.status}: ${(await r1.text()).slice(0, 200)}`); process.exit(1); }
const pr = unb64(r1.headers.get('payment-required')) ?? await r1.json();
const q = pr.accepts?.find((a) => a.network === 'eip155:77') ?? pr.accepts?.[0];
const usdc = Number(q.amount) / 1e6;
console.log(`seller   ${BASE}\nquote    ${usdc} USDC (${q.amount} atomic) → ${q.payTo}\nexpires  ${q.maxTimeoutSeconds}s after signing`);
if (has('--quote')) process.exit(0);

// 2. Would we sign this?
const bad = q.network !== 'eip155:77' ? 'network' : q.scheme !== 'exact' ? 'scheme'
  : String(q.asset).toLowerCase() !== '0x2d00000000000000000000000000000000000006' ? 'asset'
  : q.extra?.name !== 'USDC' || q.extra?.version !== '2' ? 'EIP-712 domain'
  : Number(q.extra?.decimals) !== 6 ? `decimals (${q.extra?.decimals}, POA is always 6)` : null;
if (bad) { console.log(`✗ refusing: unexpected ${bad} in the quote`); process.exit(1); }
if (usdc > MAX) { console.log(`✗ refusing: ${usdc} USDC is above --max ${MAX}`); process.exit(1); }

const pk = process.env.PAYER_PRIVATE_KEY;
if (!pk) { console.log('\nset PAYER_PRIVATE_KEY=0x… to pay (node pay.mjs --keygen makes one)'); process.exit(1); }
const me = privateKeyToAccount(pk);
const bal = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [me.address, 'latest'] }) }).then((r) => r.json());
const balance = BigInt(bal.result ?? 0);   // wire units are 18 decimals; quotes are 6
console.log(`payer    ${me.address}  (${formatUnits(balance, 18)} USDC)`);
if (balance < BigInt(q.amount) * 10n ** 12n) { console.log(`✗ not enough USDC on POA — fund ${me.address} first`); process.exit(1); }

// 3. Sign an EIP-3009 authorization for exactly the quote, and send it.
const now = Math.floor(Date.now() / 1000);
const auth = { from: me.address, to: q.payTo, value: BigInt(q.amount), validAfter: 0n,
  validBefore: BigInt(now + Number(q.maxTimeoutSeconds)), nonce: bytesToHex(randomBytes(32)) };
const signature = await me.signTypedData({
  domain: { name: 'USDC', version: '2', chainId: 77, verifyingContract: q.asset },
  types: { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] },
  primaryType: 'TransferWithAuthorization', message: auth });
const header = b64({ x402Version: 2, resource: pr.resource, accepted: q, payload: { signature,
  authorization: { ...auth, value: auth.value.toString(), validAfter: '0', validBefore: auth.validBefore.toString() } } });

// A 5xx, 429 or settlement_pending after signing is not a "no" — the money may already have
// moved. Resend the SAME header (it can't debit twice); never sign a second one meanwhile.
const t0 = Date.now();
for (let attempt = 1; ; attempt++) {
  let r = null; try { r = await fetch(URL_, { headers: { 'PAYMENT-SIGNATURE': header } }); } catch {}
  const settle = unb64(r?.headers.get('payment-response'));
  const body = r ? await r.json().catch(() => null) : null;
  if (r?.status === 200) {
    console.log(`\n✓ paid ${usdc} USDC in ${Date.now() - t0}ms · tx ${settle?.transaction}\n  https://poa.net/77/tx/${settle?.transaction}\n`);
    console.log(JSON.stringify(body, null, 2));
    process.exit(0);
  }
  const reason = settle?.errorReason ?? body?.error ?? (r ? `HTTP ${r.status}` : 'network error');
  if ((r && r.status < 500 && r.status !== 429 && reason !== 'settlement_pending') || Date.now() - t0 > 60_000) {
    console.log(`✗ ${reason}${settle?.transaction ? ` (check tx ${settle.transaction})` : ''}`); process.exit(1);
  }
  console.log(`  ${reason} — resending the same authorization (attempt ${attempt})`);
  await new Promise((res) => setTimeout(res, (Number(r?.headers.get('retry-after')) || 2) * 1000));
}
