#!/usr/bin/env node
// seller.mjs — an x402-gated paid tool server on POA chain 77.
//
// The other half of agent.mjs. The agent pays; this charges. One tool, `notarize`:
// anchor a hash to a POA block and get it back signed by the seller's key.
//
//   node --env-file=.env.seller seller.mjs [port]
//
//   GET  /                      free — what this is, what it costs
//   GET  /health                free — chain height, payTo, balance
//   GET  /notarize?hash=0x…     PAID — 402 until a PAYMENT-SIGNATURE settles
//   POST /mcp                   MCP over Streamable HTTP; tools/call notarize is PAID
//
// Settlement is SELF-SETTLE: the seller submits the payer's signed authorization straight
// to precompile 0x2d…0006 and keeps the money. POA's hosted facilitator cannot be used by
// a third party — it is pinned to the demo's payTo and price (see SECURITY-NOTES S1).
// No facilitator, no account with POA, no API key: the seller needs one key and an RPC.

import { createServer } from 'node:http';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, toHex, formatUnits, recoverTypedDataAddress, parseUnits } from 'viem';
import { stable, env, rpc, balanceOf, blockNumber, CHAIN_ID, ASSET, WIRE_DECIMALS, ATOMIC_DECIMALS,
  buildQuote, encodeHeader, decodeHeader, checkBinding, signSettle, broadcast, receiptOf, waitReceipt,
  facilitatorSettle, sellerReceipt } from './seller-lib.mjs';

const PORT = Number(process.argv[2] ?? env('SELLER_PORT', '8402'));
const PRICE = BigInt(env('SELLER_PRICE_ATOMIC', '1000'));            // 0.001 USDC
const TIMEOUT = Number(env('SELLER_MAX_TIMEOUT', '180'));
const MODE = env('SELLER_SETTLE_MODE', 'self');                      // 'self' | 'facilitator'
const LEDGER = env('SELLER_LEDGER', 'seller-ledger.json');
const account = privateKeyToAccount(env('SELLER_PRIVATE_KEY') ?? die('SELLER_PRIVATE_KEY required'));
function die(m) { console.error('✗', m); process.exit(1); }
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

// A settled authorization is remembered by (from, nonce) — the same key the precompile uses.
// x402 tells clients to retry the same PAYMENT-SIGNATURE after a 5xx, so a retry must serve
// the same result again rather than charge twice or fail. The precompile would reject the
// second settle anyway; this turns that into a correct answer instead of an error.
//
// The entry also pins the REQUEST it paid for. Without that, a client could settle once and
// then replay the same header with a different argument forever: one toll, unlimited calls.
//
// And it is written the moment the settle tx is SIGNED — before broadcast — as `pending`,
// with the tx hash. If the broadcast's response is then lost (RPC 500, deploy window, crash)
// the payment can never look like "not paid": the retry looks up that exact tx instead of
// signing a second settle for an authorization that may already have moved the money.
const ledger = existsSync(LEDGER) ? JSON.parse(readFileSync(LEDGER, 'utf8')) : {};
const save = () => writeFileSync(LEDGER, JSON.stringify(ledger, null, 2));
const remember = (k, v) => { ledger[k] = v; save(); };
const forget = (k) => { delete ledger[k]; save(); };

// Settlements run one at a time. On POA a failed tx does not consume its nonce (N6), so two
// settles signed concurrently against the same `pending` count can strand each other — and a
// second request carrying the same authorization must find the first one's ledger entry, not
// race it to the chain.
let queue = Promise.resolve();
const serial = (fn) => { const run = queue.then(fn); queue = run.catch(() => {}); return run; };

const POLLS = Number(env('SELLER_RECEIPT_POLLS', '20'));

// Test-only, for test-settle-gap.mjs: make the FIRST settlement hit the 20 Sep failure mode.
//   lost-response — the tx is broadcast, then the RPC goes dark before we hear back
//   unsent        — the RPC fails before it accepts the tx at all
// Off unless SELLER_FAULT is set, and consumed on first use.
let FAULT = env('SELLER_FAULT', '');
const takeFault = () => { const f = FAULT; FAULT = ''; return f; };

const AUTH_TYPES = { TransferWithAuthorization: [
  { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
  { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] };

// ---------- the tool ----------
// Proof of existence: this hash was known at this POA block. Deterministic, no external
// deps, and checkable by anyone who has the seller's address and the block hash.
async function notarize(hash) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash ?? '')) return { error: 'hash must be 0x + 64 hex chars (keccak256/sha256)' };
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const body = { v: 1, type: 'poa.notarization', chainId: CHAIN_ID, notary: account.address,
    hash: hash.toLowerCase(), poaBlock: Number(block.number), poaBlockHash: block.hash,
    ts: new Date().toISOString() };
  const digest = keccak256(toHex(stable(body)));
  return { ...body, digest, serverSig: await account.signMessage({ message: { raw: digest } }) };
}

// ---------- x402 gate ----------
const quoteFor = (url, error) => buildQuote({
  url, description: 'notarize(hash) — anchor a hash to a POA block, signed by the notary',
  amountAtomic: PRICE, payTo: account.address, timeoutSeconds: TIMEOUT, error });

// A pending settle is still a 402 — POA's own docs: "a missing receipt is settlement_pending
// (402), not success" — but it names the tx and says when to come back, so a client can tell
// "we may already have your money, resend the same header" from "no".
function challenge(res, url, error, paid = {}) {
  const pr = quoteFor(url, error);
  const pending = paid.pending ? { 'Retry-After': '2', 'PAYMENT-RESPONSE': encodeHeader({ success: false,
    errorReason: 'settlement_pending', transaction: paid.tx, network: `eip155:${CHAIN_ID}`, payer: paid.payer }) } : {};
  res.writeHead(402, { 'content-type': 'application/json',
    'PAYMENT-REQUIRED': encodeHeader(pr), ...pending,
    'access-control-expose-headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE, PAYMENT-SIGNATURE, Retry-After',
    'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(pr));
}

// Returns { ok:true, settlement } once the money is ours, { pending:true } while a settle we
// broadcast is unconfirmed, or { reason } when the answer is no.
// Order matters: everything free and local happens before anything that touches the chain.
async function collect(header, url, request) {
  if (!header) return { reason: 'PAYMENT-SIGNATURE header is required' };
  const payload = decodeHeader(header);
  if (!payload) return { reason: 'invalid_payload' };
  const req = quoteFor(url).accepts[0];

  // 1. Bind the signed authorization to OUR quote. The `accepted` block a client echoes back
  //    is its claim about what it agreed to pay; it is not evidence. We check the signature's
  //    own fields against the requirements we issued.
  const bad = checkBinding(payload, req);
  if (bad) return { reason: bad };
  const auth = payload.payload.authorization;

  // 2. Recover the signer ourselves. POA's facilitator /verify is pinned to its own demo
  //    payTo and price, so it cannot vet a third-party seller's quote — we verify locally.
  const signer = await recoverTypedDataAddress({
    domain: { name: 'USDC', version: '2', chainId: CHAIN_ID, verifyingContract: ASSET },
    types: AUTH_TYPES, primaryType: 'TransferWithAuthorization',
    message: { from: auth.from, to: auth.to, value: BigInt(auth.value), validAfter: BigInt(auth.validAfter),
      validBefore: BigInt(auth.validBefore), nonce: auth.nonce },
    signature: payload.payload.signature,
  }).catch(() => null);
  if (!signer || signer.toLowerCase() !== auth.from.toLowerCase()) return { reason: 'invalid_signature', payer: signer };

  // 3. From here on: one at a time.
  const key = `${auth.from.toLowerCase()}:${auth.nonce.toLowerCase()}`;
  return serial(() => settle(payload, req, key, request));
}

async function settle(payload, req, key, request) {
  const auth = payload.payload.authorization;

  // 3a. Seen this authorization before. It buys exactly one call: the same request gets the
  //     same answer back, a different one is refused.
  const hit = ledger[key];
  if (hit) {
    if (hit.request !== request) return { reason: 'authorization_already_used', payer: auth.from };
    if ((hit.status ?? 'settled') === 'settled')
      return { ok: true, key, settlement: hit.settlement, cached: hit.result, replayed: true };
    // Pending: we signed a settle for it and may have broadcast it. Resend the SAME signed tx —
    // same nonce, same hash, so it lands at most once — and ask for that hash's receipt. Never
    // sign a second settle while the first could still land.
    const r = await resolve(key, auth, await broadcast(hit.raw));
    if (r) return r;
    log(`↻ ${hit.tx.slice(0, 18)}… can never land (its nonce went to another tx) — settling afresh`);
  }

  // 4. Fail fast on an unfundable payer rather than broadcasting a doomed settle.
  const wire = parseUnits(formatUnits(BigInt(auth.value), ATOMIC_DECIMALS), WIRE_DECIMALS);
  if (await balanceOf(auth.from) < wire) return { reason: 'insufficient_funds', payer: auth.from };

  // 5. Settle, and only then serve.
  const before = await balanceOf(account.address);
  if (MODE === 'facilitator') {
    const s = await facilitatorSettle(payload, req);
    if (!s.body?.success) return { reason: s.body?.errorReason ?? `facilitator_${s.status}`, payer: auth.from };
    const settlement = { transaction: s.body.transaction, path: 'facilitator', ms: s.ms, success: true,
      network: `eip155:${CHAIN_ID}`, payer: auth.from, amount: auth.value, balanceBefore: before.toString() };
    remember(key, { status: 'settled', request, tx: s.body.transaction, settlement, result: null });
    return { ok: true, key, settlement };
  }
  const { raw, hash } = await signSettle(account, { from: auth.from, to: auth.to, value: auth.value,
    validAfter: auth.validAfter, validBefore: auth.validBefore, nonce: auth.nonce }, payload.payload.signature);
  remember(key, { status: 'pending', request, tx: hash, raw, balanceBefore: before.toString(),
    signedAt: new Date().toISOString(), result: null });

  const fault = takeFault();
  if (fault) log(`⚠ fault injected: ${fault}`);
  const b = fault === 'unsent' ? { sent: false } : await broadcast(raw);
  return (await resolve(key, auth, b, { poll: !fault }))
    ?? { reason: 'settle_failed', tx: hash, payer: auth.from };
}

// Where does a signed settle stand? Only three answers are final: mined OK, mined reverted,
// or provably dead — rejected outright, or its nonce taken by another tx while the RPC
// positively says ours has no receipt. Anything else, including "the RPC didn't answer", is
// pending. Returns null only for "provably dead", so the caller may settle afresh.
async function resolve(key, auth, b, { poll = true } = {}) {
  const entry = ledger[key];
  if (b && !b.sent && b.invalid && !b.nonceUsed) {
    forget(key);
    return { reason: 'settle_rejected', tx: entry.tx, detail: b.error, payer: auth.from };
  }
  let receipt = poll ? await waitReceipt(entry.tx, b?.nonceUsed ? 1 : POLLS) : null;
  if (!receipt && b?.nonceUsed) {
    const r = await receiptOf(entry.tx);
    if (r.receipt) receipt = r.receipt;
    else if (r.known) { forget(key); return null; }
  }
  if (receipt?.status === '0x0') { forget(key); return { reason: 'settle_failed', tx: entry.tx, payer: auth.from }; }
  if (receipt?.status !== '0x1') return { pending: true, reason: 'settlement_pending', tx: entry.tx, payer: auth.from };

  const after = await balanceOf(account.address).catch(() => null);
  const settlement = { transaction: entry.tx, path: 'self-settle', block: Number(receipt.blockNumber),
    success: true, network: `eip155:${CHAIN_ID}`, payer: auth.from, amount: auth.value,
    balanceBefore: entry.balanceBefore, balanceAfter: after?.toString() ?? null };
  // Recorded before the tool runs: if serving crashes, the next retry must know we charged.
  remember(key, { status: 'settled', request: entry.request, tx: entry.tx, settlement, result: null });
  log(`💰 +${Number(auth.value) / 10 ** ATOMIC_DECIMALS} USDC from ${auth.from.slice(0, 10)}… via self-settle ${entry.tx.slice(0, 18)}…`);
  return { ok: true, key, settlement };
}

// The paid call is remembered in full, so a retry replays the artifact the client bought
// rather than minting a fresh one against a later block.
const keep = (paid, result) => { if (paid.key && ledger[paid.key]) remember(paid.key, { ...ledger[paid.key], result }); return result; };

// ---------- MCP (Streamable HTTP) ----------
// Payment is the authentication: no accounts, no API keys, no bearer token. An agent that
// can sign an EIP-3009 authorization can call the tool; one that cannot, cannot.
const TOOLS = [{
  name: 'notarize',
  description: `Anchor a 32-byte hash to a POA chain-77 block and return it signed by the notary. Costs ${Number(PRICE) / 10 ** ATOMIC_DECIMALS} USDC per call, paid with x402 (PAYMENT-SIGNATURE header).`,
  inputSchema: { type: 'object', properties: { hash: { type: 'string', description: '0x + 64 hex chars' } }, required: ['hash'] },
}];

async function mcp(req, res, m, url) {
  const reply = (result) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result })); };
  if (m.method === 'initialize') return reply({ protocolVersion: '2025-06-18', capabilities: { tools: {} },
    serverInfo: { name: 'poa-x402-notary', version: '1.0.0' } });
  if (m.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
  if (m.method === 'tools/list') return reply({ tools: TOOLS });
  if (m.method === 'tools/call') {
    if (m.params?.name !== 'notarize') { res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, error: { code: -32602, message: `unknown tool ${m.params?.name}` } })); }
    const request = stable({ tool: 'notarize', args: m.params?.arguments ?? {} });
    const paid = await collect(req.headers['payment-signature'], url, request);
    if (!paid.ok) { log(`402 mcp/notarize — ${paid.reason}${paid.tx ? ' ' + paid.tx.slice(0, 18) + '…' : ''}`); return challenge(res, url, paid.reason, paid); }
    const out = paid.cached ?? keep(paid, await notarize(m.params?.arguments?.hash));
    await sellerReceipt(account, 'sale', { tool: 'notarize', transport: 'mcp', resource: url, priceAtomic: PRICE.toString(), hash: m.params?.arguments?.hash ?? null },
      { served: !out.error, replayed: !!paid.replayed, settlement: paid.settlement });
    res.writeHead(200, { 'content-type': 'application/json', 'PAYMENT-RESPONSE': encodeHeader(paid.settlement),
      'access-control-expose-headers': 'PAYMENT-RESPONSE' });
    return res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id,
      result: { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }], structuredContent: out, isError: !!out.error } }));
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id ?? null, error: { code: -32601, message: `unknown method ${m.method}` } }));
}

// ---------- HTTP ----------
// The URL clients reach, quoted in resource.url (never an internal origin — B6). On Fly it
// follows the app name, so renaming the app can't leave the seller quoting a stale URL.
const PUBLIC = env('SELLER_PUBLIC_URL',
  process.env.FLY_APP_NAME ? `https://${process.env.FLY_APP_NAME}.fly.dev` : `http://localhost:${PORT}`);

// A public seller must not become a way to hammer POA's public RPC, which has no rate limit of
// its own (SECURITY-NOTES §D): signatures are free to make, and every well-formed payment costs
// us chain lookups. So each client gets a per-minute budget on everything but the liveness
// probe. Behind Fly's proxy the client is `Fly-Client-IP`; elsewhere, the socket.
const RATE = Number(env('SELLER_RATE_PER_MIN', '60'));
const MAX_BODY = 64 * 1024;
const hits = new Map();
function throttled(req) {
  const ip = (env('SELLER_TRUST_PROXY') === 'fly' && req.headers['fly-client-ip']) || req.socket.remoteAddress;
  const now = Date.now();
  if (hits.size > 10_000) for (const [k, v] of hits) if (now > v.reset) hits.delete(k);
  let h = hits.get(ip);
  if (!h || now > h.reset) hits.set(ip, (h = { n: 0, reset: now + 60_000 }));
  return ++h.n > RATE ? Math.ceil((h.reset - now) / 1000) : 0;
}
const json = (res, code, o) => { res.writeHead(code, { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' }); res.end(JSON.stringify(o, null, 2)); };

const server = createServer(async (req, res) => {
  const u = new URL(req.url, PUBLIC);
  // B6 in SECURITY-NOTES: the demo leaks an internal origin in resource.url. Quote the
  // public URL the client actually asked for.
  const resourceUrl = `${PUBLIC}${u.pathname}`;
  try {
    // Liveness only — no chain calls, so a POA deploy window can't make the host think this
    // process is broken and restart it mid-settlement.
    if (u.pathname === '/livez') return json(res, 200, { ok: true });
    const wait = throttled(req);
    if (wait) { res.writeHead(429, { 'content-type': 'application/json', 'Retry-After': String(wait) });
      return res.end(JSON.stringify({ error: 'rate_limited', retryAfterSeconds: wait })); }

    if (u.pathname === '/health') return json(res, 200, { ok: true, chainId: CHAIN_ID, block: await blockNumber(),
      payTo: account.address, balance: formatUnits(await balanceOf(account.address), WIRE_DECIMALS),
      priceAtomic: PRICE.toString(), settleMode: MODE, sales: Object.keys(ledger).length });

    if (u.pathname === '/' ) return json(res, 200, { service: 'poa-x402-notary',
      price: `${Number(PRICE) / 10 ** ATOMIC_DECIMALS} USDC per call`, network: `eip155:${CHAIN_ID}`, payTo: account.address,
      paid: { http: `${PUBLIC}/notarize?hash=0x…`, mcp: `${PUBLIC}/mcp` },
      how: 'GET the paid URL, read PAYMENT-REQUIRED, sign TransferWithAuthorization, retry with PAYMENT-SIGNATURE.' });

    if (u.pathname === '/mcp') {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });
      let body = '';
      for await (const c of req) { body += c; if (body.length > MAX_BODY) return json(res, 413, { error: 'request too large' }); }
      let parsed; try { parsed = JSON.parse(body); } catch { return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
      return await mcp(req, res, parsed, resourceUrl);
    }

    if (u.pathname === '/notarize') {
      const request = stable({ tool: 'notarize', args: { hash: u.searchParams.get('hash') } });
      const paid = await collect(req.headers['payment-signature'], resourceUrl, request);
      if (!paid.ok) {
        log(`402 /notarize — ${paid.reason}${paid.tx ? ' ' + paid.tx.slice(0, 18) + '…' : ''}`);
        await sellerReceipt(account, paid.pending ? 'pending' : 'refused', { tool: 'notarize', transport: 'http', resource: resourceUrl, priceAtomic: PRICE.toString() },
          { served: false, reason: paid.reason, payer: paid.payer ?? null, tx: paid.tx ?? null });
        return challenge(res, resourceUrl, paid.reason, paid);
      }
      const out = paid.cached ?? keep(paid, await notarize(u.searchParams.get('hash')));
      await sellerReceipt(account, 'sale', { tool: 'notarize', transport: 'http', resource: resourceUrl, priceAtomic: PRICE.toString(), hash: u.searchParams.get('hash') },
        { served: !out.error, replayed: !!paid.replayed, settlement: paid.settlement });
      res.writeHead(200, { 'content-type': 'application/json', 'PAYMENT-RESPONSE': encodeHeader(paid.settlement),
        'access-control-expose-headers': 'PAYMENT-RESPONSE', 'x-content-type-options': 'nosniff' });
      return res.end(JSON.stringify(out, null, 2));
    }
    json(res, 404, { error: 'not found' });
  } catch (e) {
    log('✗', e.message);
    json(res, 500, { error: e.message });
  }
});

server.listen(PORT, async () => {
  log(`seller  ${account.address}`);
  log(`payTo   ${account.address}  balance ${formatUnits(await balanceOf(account.address), WIRE_DECIMALS)} USDC`);
  log(`price   ${PRICE} atomic = ${Number(PRICE) / 10 ** ATOMIC_DECIMALS} USDC · settle=${MODE} · chain ${CHAIN_ID} @ ${await blockNumber()}`);
  log(`listen  ${PUBLIC}  (GET /notarize?hash=0x… · POST /mcp)`);
});
