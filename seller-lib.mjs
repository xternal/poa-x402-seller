// Seller-side helpers for x402-on-POA. The payer's half lives in agent.mjs; this is the
// other half — quoting a price, reading a PAYMENT-SIGNATURE, and getting the money in.
//
// Everything here is derived from what the live chain does, not from the x402 spec:
//   - the quote shape mirrors the demo's PAYMENT-REQUIRED byte for byte (see README),
//   - the settle calldata mirrors an observed facilitator settlement tx,
//   - value stays in 6-decimal atomic units all the way to the precompile, which does the
//     6→18 scaling itself (decoded from tx 0xc54bb93a…, value field = 0x2710 = 10000).

import { keccak256, toHex } from 'viem';
import { appendFileSync } from 'node:fs';

// Deterministic JSON: keys sorted at every depth, so a hash over it is reproducible by anyone.
// Same function as the payer's (mandate.mjs), kept here so the seller stands on its own.
export const stable = (v) =>
  Array.isArray(v) ? '[' + v.map(stable).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
  : JSON.stringify(v);

export const env = (k, d) => process.env[k] ?? d;
export const RPC = env('POA_RPC', 'https://rpc.poa.net');
export const CHAIN_ID = Number(env('POA_CHAIN_ID', '77'));
export const NETWORK = `eip155:${CHAIN_ID}`;
export const FACILITATOR = env('POA_FACILITATOR', 'https://poa.net/77/x402/facilitator');
export const ASSET = env('POA_NATIVE_AUTH', '0x2d00000000000000000000000000000000000006');
export const WIRE_DECIMALS = Number(env('POA_WIRE_DECIMALS', '18'));
export const ATOMIC_DECIMALS = 6;           // x402 quote units — NOT the wire units
export const SELLER_RECEIPTS = env('SELLER_RECEIPTS_FILE', 'seller-receipts.jsonl');

// ---------- chain ----------
let rpcId = 0;
export async function rpc(method, params = []) {
  const r = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++rpcId, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}
export const balanceOf = async (addr) => BigInt(await rpc('eth_getBalance', [addr, 'latest']));
export const blockNumber = async () => Number(await rpc('eth_blockNumber'));

// ---------- the quote ----------
// Mirrors the demo 402 exactly: base64 JSON in a PAYMENT-REQUIRED header, `accepts[0]`
// carrying the atomic amount and our own payTo.
export function buildQuote({ url, description, amountAtomic, payTo, timeoutSeconds = 180, mimeType = 'application/json', error }) {
  const accepts = {
    amount: String(amountAtomic),
    asset: ASSET,
    extra: { assetTransferMethod: 'eip3009', decimals: ATOMIC_DECIMALS, kind: 'native',
      name: 'USDC', paymentFlow: 'authorization', symbol: 'USDC', version: '2' },
    maxTimeoutSeconds: timeoutSeconds,
    network: NETWORK,
    payTo,
    scheme: 'exact',
  };
  return { accepts: [accepts], error, extensions: {}, resource: { description, mimeType, url }, x402Version: 2 };
}
export const encodeHeader = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
export function decodeHeader(h) {
  if (!h) return null;
  try { return JSON.parse(Buffer.from(h, 'base64').toString('utf8')); } catch {}
  try { return JSON.parse(h); } catch {}
  return null;
}

// ---------- seller-side binding checks ----------
// The seller must never trust the `accepted` block the client echoes back: that is the
// client's claim about what it agreed to pay. We check the *signed authorization* against
// the requirements WE quoted, and we hand the facilitator OUR requirements, not theirs.
// (N1 in SECURITY-NOTES: nothing caps validBefore on-chain, so the resource server caps it.)
export function checkBinding(payload, req, { maxWindowSeconds = req.maxTimeoutSeconds } = {}) {
  const a = payload?.payload?.authorization;
  if (!a || !payload?.payload?.signature) return 'missing_authorization';
  if (String(a.to).toLowerCase() !== String(req.payTo).toLowerCase()) return 'recipient_mismatch';
  if (BigInt(a.value) !== BigInt(req.amount)) return 'authorization_value_mismatch';
  const now = Math.floor(Date.now() / 1000);
  if (Number(a.validBefore) <= now) return 'authorization_valid_before';
  if (Number(a.validAfter) > now) return 'authorization_valid_after';
  if (Number(a.validBefore) - now > maxWindowSeconds) return 'authorization_window_too_long';
  if (payload.accepted && String(payload.accepted.asset).toLowerCase() !== ASSET.toLowerCase()) return 'asset_mismatch';
  return null;
}

// ---------- hosted facilitator ----------
// Envelope keys are load-bearing: the facilitator reads x402Version out of paymentPayload,
// so `{payload, requirements}` answers invalid_x402_version instead of a useful verdict.
async function facilitator(path, payload, requirements) {
  const t0 = Date.now();
  const r = await fetch(`${FACILITATOR}/${path}`, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ x402Version: payload.x402Version ?? 2, paymentPayload: payload, paymentRequirements: requirements }) });
  const text = await r.text();
  let body = null; try { body = JSON.parse(text); } catch {}
  return { status: r.status, body, text, ms: Date.now() - t0 };
}
export const facilitatorVerify = (payload, req) => facilitator('verify', payload, req);
export const facilitatorSettle = (payload, req) => facilitator('settle', payload, req);

// ---------- self-settle ----------
// transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)
// selector 0xe3ee160e — the same call the facilitator's settler makes into 0x2d…0006.
const pad = (h) => h.replace(/^0x/, '').padStart(64, '0');
export function settleCalldata({ from, to, value, validAfter, validBefore, nonce }, signature) {
  const s = signature.replace(/^0x/, '');
  if (s.length !== 130) throw new Error(`signature must be 65 bytes, got ${s.length / 2}`);
  const r = s.slice(0, 64), sv = s.slice(64, 128);
  let v = parseInt(s.slice(128, 130), 16);
  if (v < 27) v += 27;                       // viem emits 1b/1c, but accept 00/01 too
  return '0xe3ee160e' + [from, to, toHex(BigInt(value)), toHex(BigInt(validAfter)),
    toHex(BigInt(validBefore)), nonce, toHex(v), '0x' + r, '0x' + sv].map(pad).join('');
}

// Submitting a settlement is split in three so a seller can write down what it is about to
// do BEFORE doing it. The tx hash is keccak(raw) and known before broadcast (verified live:
// the RPC returns the same hash), so a lost response never leaves us not knowing which tx to
// look for. There is no eth_getLogs and no eth_call on the public RPC — the receipt of a hash
// we already hold is the ONLY way to learn whether a settlement landed.
export async function signSettle(account, authorization, signature) {
  const data = settleCalldata(authorization, signature);
  const nonce = Number(await rpc('eth_getTransactionCount', [account.address, 'pending']));
  const raw = await account.signTransaction({ to: ASSET, data, value: 0n, nonce,
    gasPrice: 0n, gas: 100000n, chainId: CHAIN_ID, type: 'legacy' });
  return { raw, hash: keccak256(raw), nonce };
}

// Resending the same signed tx is idempotent: before it mines POA returns the same hash again;
// after, it answers `nonce too low` — which it also says if a DIFFERENT tx took that nonce, so
// that error alone never tells you whether yours landed. Callers check the receipt.
//
// `invalid` marks POA's own validation rejection ("Invalid transaction: …") — a definite no.
// Any other failure (HTTP 500, timeout, garbage body) means we don't know if it was accepted.
export async function broadcast(raw) {
  try { return { sent: true, hash: await rpc('eth_sendRawTransaction', [raw]) }; }
  catch (e) { return { sent: false, invalid: /Invalid transaction/i.test(e.message),
    nonceUsed: /nonce too low/i.test(e.message), error: e.message }; }
}

// { known: true, receipt } — the RPC answered (receipt may be null: not mined).
// { known: false }          — the RPC did not answer. "Couldn't ask" is not "not there";
//                             during a deploy window the two look the same.
export async function receiptOf(hash) {
  try { return { known: true, receipt: await rpc('eth_getTransactionReceipt', [hash]) }; }
  catch { return { known: false, receipt: null }; }
}

export async function waitReceipt(hash, tries = 20) {
  for (let i = 0; i < tries; i++) {
    const r = await receiptOf(hash);
    if (r.receipt) return r.receipt;
    await new Promise((res) => setTimeout(res, 1000));
  }
  return null;
}

// Submit someone else's signed authorization ourselves. EIP-3009 authorizations are bearer
// instruments (SECURITY-NOTES B3) — the precompile accepts any caller, so a seller never
// needs the hosted facilitator. One-shot convenience for probes; seller.mjs uses the parts.
export async function selfSettle(account, authorization, signature) {
  const { raw, hash } = await signSettle(account, authorization, signature);
  const t0 = Date.now();
  const b = await broadcast(raw);
  if (!b.sent) throw new Error(b.error);
  const receipt = await waitReceipt(hash);
  return { hash, receipt, ok: receipt?.status === '0x1', ms: Date.now() - t0 };
}

// ---------- seller receipts ----------
// Same shape and signing rule as the payer's receipts so one verifier reads both files:
// keccak over the canonical body, signed by the key named inside it.
export async function sellerReceipt(account, kind, intent, outcome, file = SELLER_RECEIPTS) {
  const body = { v: 2, chainId: CHAIN_ID, role: 'seller', seller: account.address,
    kind, intent, outcome, ts: new Date().toISOString() };
  const hash = keccak256(toHex(stable(body)));
  const sig = await account.signMessage({ message: { raw: hash } });
  appendFileSync(file, JSON.stringify({ ...body, hash, sig }) + '\n');
  return { hash, sig };
}
