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
import { createHash } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, toHex, formatUnits, recoverTypedDataAddress, parseUnits } from 'viem';
import { stable, env, rpc, balanceOf, blockNumber, CHAIN_ID, ASSET, WIRE_DECIMALS, ATOMIC_DECIMALS,
  buildQuote, encodeHeader, decodeHeader, checkBinding, signSettle, broadcast, receiptOf, waitReceipt,
  facilitatorSettle, sellerReceipt } from './seller-lib.mjs';

const PORT = Number(process.argv[2] ?? env('SELLER_PORT', '8402'));
const PRICE = BigInt(env('SELLER_PRICE_ATOMIC', '1000'));            // notarize: 0.001 USDC
const FETCH_PRICE = BigInt(env('SELLER_PRICE_FETCH_ATOMIC', '2000')); // premium_fetch: 0.002 USDC
const FETCH_BYTES = Number(env('SELLER_FETCH_MAX_BYTES', String(512 * 1024)));
const FETCH_MS = Number(env('SELLER_FETCH_TIMEOUT_MS', '10000'));
const FETCH_HOPS = Number(env('SELLER_FETCH_MAX_REDIRECTS', '3'));
const FETCH_UA = env('SELLER_FETCH_UA', 'poa-x402-seller/1.0 (+https://poa-x402-seller.fly.dev/llms.txt)');
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

// ---------- the tools ----------
// Both sell the same thing underneath: a statement signed by this server and anchored to a POA
// block, so the buyer gets something citable rather than something to take on trust.

const atomicToUsdc = (a) => Number(a) / 10 ** ATOMIC_DECIMALS;

// Everything the notary signs carries the block it was made at, so "when" is not our word for it.
async function anchor(body) {
  const block = await rpc('eth_getBlockByNumber', ['latest', false]);
  const full = { ...body, chainId: CHAIN_ID, notary: account.address,
    poaBlock: Number(block.number), poaBlockHash: block.hash, ts: new Date().toISOString() };
  const digest = keccak256(toHex(stable(full)));
  return { ...full, digest, serverSig: await account.signMessage({ message: { raw: digest } }) };
}

// notarize(hash) — proof of existence: this hash was known by this block.
const validNotarize = ({ hash }) => (/^0x[0-9a-fA-F]{64}$/.test(hash ?? '') ? null : 'hash must be 0x + 64 hex chars (keccak256 or sha256)');
const notarize = ({ hash }) => anchor({ v: 1, type: 'poa.notarization', hash: hash.toLowerCase() });

// premium_fetch(url) — fetch a page and sign what it said, anchored to a block: status, final URL
// after redirects, the sha256 of the whole body, and a text extract. A citable fact, not a proxy.
//
// A paid fetcher is an open proxy if you let it be, so: http(s) only, no credentials in the URL, no
// private or link-local address (every DNS answer is checked, and every redirect hop again), a byte
// cap, a timeout, GET only, no client headers forwarded, and robots.txt is honoured. The URL is
// checked BEFORE payment — we do not charge for a request we will not serve.
const BLOCKED_HOST = /^(localhost|metadata\.google\.internal|.*\.(local|internal|localhost|test|invalid|onion))$/i;
const OK_PORT = new Set(['', '80', '443', '8080', '8443']);

function privateAddress(ip) {
  if (ip.includes(':')) {
    const v = ip.toLowerCase();
    if (v.startsWith('::ffff:') && v.includes('.')) return privateAddress(v.split(':').pop());
    return v === '::1' || v === '::' || /^f[cd]/.test(v) || v.startsWith('fe80');
  }
  const [a, b] = ip.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

async function badAddress(raw) {
  let u; try { u = new URL(raw); } catch { return `not a URL: ${String(raw).slice(0, 80)}`; }
  if (!/^https?:$/.test(u.protocol)) return `scheme ${u.protocol} is not allowed — http and https only`;
  if (u.username || u.password) return 'credentials in the URL are not allowed';
  if (BLOCKED_HOST.test(u.hostname)) return `host ${u.hostname} is not allowed`;
  if (!OK_PORT.has(u.port)) return `port ${u.port} is not allowed`;
  const addrs = await lookup(u.hostname, { all: true }).catch(() => null);
  if (!addrs?.length) return `cannot resolve ${u.hostname}`;
  const priv = addrs.find((a) => privateAddress(a.address));
  if (priv) return `${u.hostname} resolves to a private address (${priv.address})`;
  return null;
}

// A deliberately small robots.txt reader: the groups for * and for our own user-agent, longest
// matching rule wins, Allow beats an equally specific Disallow. Cached for 15 minutes per origin.
const robotsCache = new Map();
function robotsRules(txt) {
  const groups = []; let current = null;
  for (const line of txt.split('\n')) {
    const [rawKey, ...rest] = line.split('#')[0].split(':');
    const key = rawKey.trim().toLowerCase(), value = rest.join(':').trim();
    if (!key) continue;
    if (key === 'user-agent') { if (!current?.fresh) current = { agents: [], rules: [], fresh: true }, groups.push(current); current.agents.push(value.toLowerCase()); }
    else if (current && (key === 'disallow' || key === 'allow')) { current.fresh = false; current.rules.push({ allow: key === 'allow', path: value }); }
  }
  const mine = groups.filter((g) => g.agents.some((a) => FETCH_UA.toLowerCase().startsWith(a.split('/')[0]) && a !== '*'));
  const star = groups.filter((g) => g.agents.includes('*'));
  return (mine.length ? mine : star).flatMap((g) => g.rules);
}
function robotsAllows(rules, path) {
  let best = null;
  for (const r of rules) {
    if (r.path === '') continue;                              // "Disallow:" with nothing means allow all
    const prefix = r.path.replace(/\*.*$/, '');
    if (!path.startsWith(prefix)) continue;
    if (!best || prefix.length > best.len || (prefix.length === best.len && r.allow)) best = { len: prefix.length, allow: r.allow };
  }
  return best ? best.allow : true;
}
async function robotsBlocks(raw) {
  const u = new URL(raw);
  let entry = robotsCache.get(u.origin);
  if (!entry || Date.now() - entry.at > 900_000) {
    const txt = await fetch(`${u.origin}/robots.txt`, { signal: AbortSignal.timeout(5000), headers: { 'user-agent': FETCH_UA } })
      .then((r) => (r.ok ? r.text() : '')).catch(() => '');
    entry = { at: Date.now(), rules: robotsRules(txt.slice(0, 64 * 1024)) };
    if (robotsCache.size > 500) robotsCache.clear();
    robotsCache.set(u.origin, entry);
  }
  return robotsAllows(entry.rules, u.pathname) ? null : `robots.txt on ${u.host} disallows ${u.pathname} for our fetcher`;
}

async function validFetch({ url, maxChars }) {
  if (maxChars !== undefined && !(Number(maxChars) >= 200 && Number(maxChars) <= 40000)) return 'maxChars must be between 200 and 40000';
  return (await badAddress(url)) ?? (await robotsBlocks(url));
}

const TEXTUAL = /^(text\/|application\/(json|xml|xhtml\+xml|javascript|x-ndjson))/i;
function extractText(buf, contentType, cap) {
  if (!TEXTUAL.test(contentType ?? '')) return null;
  let t = buf.toString('utf8');
  if (/html|xml/i.test(contentType)) {
    t = t.replace(/<(script|style|noscript|template|svg)[\s\S]*?<\/\1>/gi, ' ').replace(/<!--[\s\S]*?-->/g, ' ')
      .replace(/<(\/p|br|\/div|\/li|\/h[1-6]|\/tr)>/gi, '\n').replace(/<[^>]+>/g, ' ');
    const ent = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", nbsp: ' ' };
    t = t.replace(/&(\w+|#\d+);/g, (m, k) => ent[k] ?? m);
  }
  t = t.split('\n').map((l) => l.replace(/[ \t\u00a0]+/g, ' ').trim()).filter(Boolean).join('\n');
  return t.length > cap ? t.slice(0, cap) : t;
}

async function premiumFetch({ url, maxChars }) {
  const cap = Number(maxChars ?? 8000);
  const t0 = Date.now();
  let current = url, hops = [], res = null;
  for (let hop = 0; ; hop++) {
    res = await fetch(current, { redirect: 'manual', signal: AbortSignal.timeout(FETCH_MS),
      headers: { 'user-agent': FETCH_UA, accept: 'text/html,application/xhtml+xml,text/plain,application/json;q=0.9,*/*;q=0.5' } })
      .catch((e) => ({ error: e.name === 'TimeoutError' ? `timed out after ${FETCH_MS}ms` : e.message }));
    if (res.error) return { error: `fetch failed: ${res.error}` };
    const to = res.headers.get('location');
    if ([301, 302, 303, 307, 308].includes(res.status) && to) {
      if (hop >= FETCH_HOPS) return { error: `more than ${FETCH_HOPS} redirects` };
      const next = new URL(to, current).toString();
      const bad = await badAddress(next);
      if (bad) return { error: `redirect to a blocked address: ${bad}` };
      hops.push(next); current = next; continue;
    }
    break;
  }
  // Read with a hard byte cap: a paid fetch must not be a way to make us download a DVD.
  const chunks = []; let size = 0, truncated = false;
  const reader = res.body?.getReader?.();
  if (reader) for (;;) {
    const { done, value } = await reader.read().catch(() => ({ done: true }));
    if (done) break;
    size += value.length;
    if (size > FETCH_BYTES) { chunks.push(Buffer.from(value).subarray(0, Math.max(0, FETCH_BYTES - (size - value.length)))); truncated = true; await reader.cancel().catch(() => {}); break; }
    chunks.push(Buffer.from(value));
  }
  const body = Buffer.concat(chunks);
  const contentType = res.headers.get('content-type');
  return anchor({
    v: 1, type: 'poa.fetch-attestation', url, finalUrl: current, redirects: hops,
    httpStatus: res.status, contentType, bytes: body.length, truncated,
    sha256: '0x' + createHash('sha256').update(body).digest('hex'),
    fetchedInMs: Date.now() - t0,
    text: extractText(body, contentType, cap),
  });
}

// What is for sale. One place, so both transports and the public pages agree on price and shape.
const TOOLKIT = {
  notarize: {
    price: PRICE, path: '/notarize', validate: validNotarize, run: notarize,
    args: (u) => ({ hash: u.searchParams.get('hash') }),
    blurb: 'Anchor a 32-byte hash to a POA chain-77 block and return it signed by the notary — proof the hash existed by that block.',
    inputSchema: { type: 'object', properties: { hash: { type: 'string', description: '0x + 64 hex chars (keccak256 or sha256)' } }, required: ['hash'] },
  },
  premium_fetch: {
    price: FETCH_PRICE, path: '/fetch', validate: validFetch, run: premiumFetch,
    args: (u) => ({ url: u.searchParams.get('url'), ...(u.searchParams.has('maxChars') && { maxChars: u.searchParams.get('maxChars') }) }),
    blurb: 'Fetch a public URL and return what it said, signed and anchored to a POA block: HTTP status, final URL after redirects, sha256 of the whole body, and a text extract. Honours robots.txt; refuses private addresses. A citable record, not a proxy.',
    inputSchema: { type: 'object', properties: {
      url: { type: 'string', description: 'http(s) URL on a public address' },
      maxChars: { type: 'integer', description: 'characters of extracted text to return, 200–40000 (default 8000)' } }, required: ['url'] },
  },
};
const toolByPath = Object.fromEntries(Object.entries(TOOLKIT).map(([name, t]) => [t.path, name]));

// ---------- x402 gate ----------
const quoteFor = (url, error, tool = 'notarize') => buildQuote({
  url, description: `${tool} — ${TOOLKIT[tool].blurb}`,
  amountAtomic: TOOLKIT[tool].price, payTo: account.address, timeoutSeconds: TIMEOUT, error });

// A pending settle is still a 402 — POA's own docs: "a missing receipt is settlement_pending
// (402), not success" — but it names the tx and says when to come back, so a client can tell
// "we may already have your money, resend the same header" from "no".
function challenge(res, url, error, paid = {}, tool = 'notarize') {
  const pr = quoteFor(url, error, tool);
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
async function collect(header, url, request, tool = 'notarize') {
  if (!header) return { reason: 'PAYMENT-SIGNATURE header is required' };
  const payload = decodeHeader(header);
  if (!payload) return { reason: 'invalid_payload' };
  const req = quoteFor(url, undefined, tool).accepts[0];

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

  // 3. From here on: one at a time. Everything past this point concerns an authorization that
  //    really was signed by `from` — the only kind of refusal worth a receipt (see the handler).
  const key = `${auth.from.toLowerCase()}:${auth.nonce.toLowerCase()}`;
  return { ...(await serial(() => settle(payload, req, key, request))), authenticated: true };
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

// One road for both transports. The tool's own validation runs BEFORE the gate: an unusable
// request is refused free of charge, so nobody pays for an answer we were never going to give.
async function paidCall(name, args, header, resourceUrl) {
  const t = TOOLKIT[name];
  if (!t) return { unknown: `unknown tool ${name}` };
  const invalid = await t.validate(args ?? {});
  if (invalid) return { invalid, tool: name };
  const request = stable({ tool: name, args: args ?? {} });
  const paid = await collect(header, resourceUrl, request, name);
  if (!paid.ok) return { gate: paid, tool: name };
  return { ok: true, tool: name, paid, out: paid.cached ?? keep(paid, await t.run(args ?? {})) };
}

// ---------- MCP (Streamable HTTP) ----------
// Payment is the authentication: no accounts, no API keys, no bearer token. An agent that
// can sign an EIP-3009 authorization can call the tool; one that cannot, cannot.
const TOOLS = Object.entries(TOOLKIT).map(([name, t]) => ({
  name,
  description: `${t.blurb} Costs ${atomicToUsdc(t.price)} USDC per call, paid with x402 (PAYMENT-SIGNATURE header); the 402 carries the quote.`,
  inputSchema: t.inputSchema,
}));

async function mcp(req, res, m, url) {
  const reply = (result) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result })); };
  if (m.method === 'initialize') return reply({ protocolVersion: '2025-06-18', capabilities: { tools: {} },
    serverInfo: { name: 'poa-x402-notary', version: '1.0.0' } });
  if (m.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
  if (m.method === 'tools/list') return reply({ tools: TOOLS });
  if (m.method === 'tools/call') {
    const name = m.params?.name, args = m.params?.arguments ?? {};
    const r = await paidCall(name, args, req.headers['payment-signature'], url);
    const fail = (text) => { res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text }], isError: true } })); };
    if (r.unknown) return fail(`${r.unknown}. Available: ${Object.keys(TOOLKIT).join(', ')}.`);
    if (r.invalid) { log(`400 mcp/${name} — ${r.invalid}`); return fail(`${name}: ${r.invalid} — nothing was charged.`); }
    if (r.gate) { log(`402 mcp/${name} — ${r.gate.reason}${r.gate.tx ? ' ' + r.gate.tx.slice(0, 18) + '…' : ''}`); return challenge(res, url, r.gate.reason, r.gate, name); }
    await sellerReceipt(account, 'sale', { tool: name, transport: 'mcp', resource: url, priceAtomic: TOOLKIT[name].price.toString(), args },
      { served: !r.out.error, replayed: !!r.paid.replayed, settlement: r.paid.settlement });
    res.writeHead(200, { 'content-type': 'application/json', 'PAYMENT-RESPONSE': encodeHeader(r.paid.settlement),
      'access-control-expose-headers': 'PAYMENT-RESPONSE' });
    return res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id,
      result: { content: [{ type: 'text', text: JSON.stringify(r.out, null, 2) }], structuredContent: r.out, isError: !!r.out.error } }));
  }
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ jsonrpc: '2.0', id: m.id ?? null, error: { code: -32601, message: `unknown method ${m.method}` } }));
}

// ---------- the public face ----------
// The paid endpoints answer machines. These answer people and crawlers: a public service should be
// findable and legible, and an agent reading robots.txt or llms.txt should learn what this costs
// without paying to find out. Static, no chain calls, never rate-limited.
let OG = null;
try { OG = readFileSync('og.png'); } catch { /* not shipped in this build */ }

const page = (base, priceUsdc, payTo) => `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>A tollbooth for AI agents — pay-per-call tool server on POA</title>
<meta name="description" content="A web service that charges ${priceUsdc} USDC per call over HTTP 402 / x402, settles the payment itself, and needs no account or API key. Live, open source, MIT.">
<link rel="canonical" href="${base}/">
<meta property="og:type" content="website">
<meta property="og:url" content="${base}/">
<meta property="og:title" content="A tollbooth for AI agents">
<meta property="og:description" content="${priceUsdc} USDC per call over HTTP 402. Payment is the authentication: no account, no API key, no invoice.">
<meta property="og:image" content="${base}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="A tollbooth for AI agents">
<meta name="twitter:description" content="${priceUsdc} USDC per call over HTTP 402. Payment is the authentication.">
<meta name="twitter:image" content="${base}/og.png">
<script type="application/ld+json">${JSON.stringify({
  '@context': 'https://schema.org', '@type': 'SoftwareApplication',
  name: 'poa-x402-seller', url: `${base}/`, applicationCategory: 'DeveloperApplication',
  description: `A pay-per-call tool server on POA chain 77. Charges ${priceUsdc} USDC per request over HTTP 402 (x402) and settles the payment itself.`,
  operatingSystem: 'Any', license: 'https://opensource.org/licenses/MIT',
  codeRepository: 'https://github.com/xternal/poa-x402-seller',
  author: { '@type': 'Person', name: 'Pavel Guzhikov', url: 'https://guzh.uk' },
  offers: { '@type': 'Offer', price: String(priceUsdc), priceCurrency: 'USDC' },
})}</script>
<style>
  :root { color-scheme: dark light; --bg:#0b0f16; --fg:#e8eef4; --muted:#93a4b5; --accent:#3ddc97; --line:#1e2938; }
  @media (prefers-color-scheme: light) { :root { --bg:#fbfcfd; --fg:#12181f; --muted:#5a6b7c; --accent:#0a7f52; --line:#dde5ec; } }
  body { background:var(--bg); color:var(--fg); font:16px/1.65 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin:0; padding:48px 20px; }
  main { max-width:44rem; margin:0 auto; }
  h1 { font-size:2.1rem; line-height:1.15; margin:0 0 .3em; letter-spacing:-.02em; }
  h2 { font-size:1.1rem; margin:2.2em 0 .6em; }
  code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.9em; }
  pre { background:color-mix(in srgb, var(--fg) 7%, transparent); padding:14px 16px; border-radius:10px; overflow-x:auto; border:1px solid var(--line); }
  .lede { font-size:1.15rem; color:var(--fg); }
  .muted { color:var(--muted); }
  a { color:var(--accent); }
  table { border-collapse:collapse; width:100%; margin:.5em 0 0; }
  td,th { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); font-size:.95rem; vertical-align:top; }
  footer { margin-top:3em; padding-top:1.2em; border-top:1px solid var(--line); color:var(--muted); font-size:.92rem; }
</style>
<main>
  <p class="muted"><code>HTTP/2 402 Payment Required</code></p>
  <h1>A tollbooth for AI agents</h1>
  <p class="lede">This service sells two tools, <strong>from ${priceUsdc} USDC per call</strong>. It settles each payment itself and asks nobody for an account. Payment is the authentication: no signup, no API key, no invoice.</p>

  <h2>How it works</h2>
  <ol>
    <li>You request a paid endpoint. It answers <code>402</code> with a price quote in a <code>PAYMENT-REQUIRED</code> header.</li>
    <li>You sign a payment authorisation for exactly that quote and retry the same request with a <code>PAYMENT-SIGNATURE</code> header.</li>
    <li>This server submits your payment to POA chain 77 itself, waits for it to be final — about two seconds — and then serves the result.</li>
  </ol>

  <h2>What is for sale</h2>
  <table>
    <tr><th>notarize</th><td><strong>${atomicToUsdc(TOOLKIT.notarize.price)} USDC</strong> · <code>GET /notarize?hash=0x…</code><br>Anchors a 32-byte hash to a POA block and signs it, so anyone can later check the hash existed by then.</td></tr>
    <tr><th>premium_fetch</th><td><strong>${atomicToUsdc(TOOLKIT.premium_fetch.price)} USDC</strong> · <code>GET /fetch?url=https://…</code><br>Fetches a public URL and signs what it said: HTTP status, final URL after redirects, sha256 of the whole body, and a text extract — a record you can cite, anchored to a block. Honours robots.txt, refuses private addresses, caps size and time.</td></tr>
    <tr><th>Both</th><td>Also available as MCP tools at <code>POST /mcp</code>. Paid in native USDC on POA chain 77 (<code>eip155:77</code>) to <code>${payTo}</code>.</td></tr>
    <tr><th>Free</th><td><code>GET /health</code> · <code>GET /livez</code> · MCP <code>initialize</code> and <code>tools/list</code> · an unusable request is refused without charge</td></tr>
  </table>

  <h2>See the price without paying</h2>
  <pre>curl -si ${base}/notarize | head -1
curl -s  ${base}/health</pre>

  <h2>Questions</h2>
  <p><strong>Do I need an account?</strong> No. There is nothing to sign up for. The only thing this server checks is that a valid payment for its own quote has settled.</p>
  <p><strong>What stops someone paying once and calling forever?</strong> Each payment authorisation buys exactly one call: it is pinned to the request it paid for, and a repeat of the same request returns the same result rather than charging again.</p>
  <p><strong>What if the payment settles but the answer never arrives?</strong> The settlement is written down before it is broadcast. Retry the identical request and you get what you paid for; you are never charged twice.</p>
  <p><strong>Is premium_fetch an open proxy?</strong> No. It only takes http and https URLs on public addresses, checks every DNS answer and every redirect, obeys robots.txt, caps the response and the time, forwards none of your headers, and never does anything but GET. The URL is checked before payment, so a blocked one costs nothing.</p>
  <p><strong>Can I run my own?</strong> Yes — it is MIT licensed, about 230 lines, and needs one key and an RPC URL. <a href="https://github.com/xternal/poa-x402-seller">Source on GitHub</a>.</p>

  <footer>
    Built by <a href="https://guzh.uk">Pavel Guzhikov</a> · <a href="https://github.com/xternal/poa-x402-seller">source</a> ·
    <a href="https://ko-fi.com/pavelg">buy me a coffee</a> · <a href="${base}/llms.txt">llms.txt</a>
  </footer>
</main>
`;

const ROBOTS = (base) => `# Everything here is public. Crawlers and AI agents are welcome.
User-agent: *
Allow: /

User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Google-Extended
Allow: /

Sitemap: ${base}/sitemap.xml
`;

const SITEMAP = (base) => `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${base}/</loc><changefreq>monthly</changefreq><priority>1.0</priority></url>
</urlset>
`;

const LLMS = (base, priceUsdc, payTo) => `# poa-x402-seller

> A pay-per-call tool server on POA chain 77. It charges ${priceUsdc} USDC per request using x402
> (HTTP 402 Payment Required) and settles the payment itself, with no facilitator, account or API key.

## What you can buy
- notarize(hash): anchors a 32-byte hash to a POA block and returns it signed by the notary, as
  proof the hash existed by that block. ${atomicToUsdc(TOOLKIT.notarize.price)} USDC per call.
  HTTP: GET ${base}/notarize?hash=0x<64 hex>
- premium_fetch(url, maxChars?): fetches a public URL and returns what it said, signed and anchored
  to a POA block: httpStatus, finalUrl after redirects, contentType, bytes, sha256 of the whole
  body, and a text extract (default 8000 chars, max 40000). ${atomicToUsdc(TOOLKIT.premium_fetch.price)} USDC per call.
  HTTP: GET ${base}/fetch?url=https://example.com
  Limits: http(s) only, public addresses only (every DNS answer and redirect hop is checked),
  robots.txt honoured, GET only, no client headers forwarded, response and time capped. An
  unusable URL is refused with HTTP 400 and no charge.
All payments go to ${payTo}.

## How to pay (for an agent)
1. GET the paid endpoint. You receive HTTP 402 and a quote, base64 JSON, in the
   PAYMENT-REQUIRED header: amount (6-decimal atomic units), asset, payTo, maxTimeoutSeconds.
2. Sign an EIP-3009 TransferWithAuthorization for exactly that quote. EIP-712 domain: name USDC,
   version 2, chainId 77, verifyingContract 0x2d00000000000000000000000000000000000006.
3. Retry the same request with a PAYMENT-SIGNATURE header: base64 of
   {x402Version:2, resource, accepted, payload:{signature, authorization}}.
4. You get 200 with the result, and the settlement transaction in the PAYMENT-RESPONSE header.
   One authorisation buys one call; an identical retry returns the same result and is not charged twice.
   If the answer is 402 settlement_pending, resend the same header — the payment may already be on-chain.

## MCP
POST ${base}/mcp speaks MCP over Streamable HTTP. initialize and tools/list are free; tools/call is
paid with the same PAYMENT-SIGNATURE header. Each tool has its own price — read it from tools/list or
from the 402 quote, never assume.

## Free endpoints
${base}/health (chain height, payee, price, sales), ${base}/livez (liveness).

## Source and licence
https://github.com/xternal/poa-x402-seller — MIT. Author: Pavel Guzhikov, https://guzh.uk
`;

// ---------- HTTP ----------
// The URL clients reach, quoted in resource.url (never an internal origin — B6). On Fly it
// follows the app name, so renaming the app can't leave the seller quoting a stale URL.
const PRICE_USDC = Number(PRICE) / 10 ** ATOMIC_DECIMALS;
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
    const serve = (type, body, maxAge = 3600) => { res.writeHead(200, { 'content-type': type, 'cache-control': `public, max-age=${maxAge}`, 'x-content-type-options': 'nosniff' }); res.end(body); };
    if (u.pathname === '/robots.txt') return serve('text/plain; charset=utf-8', ROBOTS(PUBLIC));
    if (u.pathname === '/sitemap.xml') return serve('application/xml; charset=utf-8', SITEMAP(PUBLIC));
    if (u.pathname === '/llms.txt') return serve('text/plain; charset=utf-8', LLMS(PUBLIC, PRICE_USDC, account.address));
    if (u.pathname === '/og.png' && OG) return serve('image/png', OG, 86400);
    const wait = throttled(req);
    if (wait) { res.writeHead(429, { 'content-type': 'application/json', 'Retry-After': String(wait) });
      return res.end(JSON.stringify({ error: 'rate_limited', retryAfterSeconds: wait })); }

    // What an operator (and monitor.mjs) needs: is the seller itself fine, is POA reachable —
    // reported separately, because a POA deploy window is not our outage — and is anything
    // stuck in settlement_pending.
    if (u.pathname === '/health') {
      const entries = Object.values(ledger);
      const pending = entries.filter((e) => e.status === 'pending');
      const oldest = pending.reduce((a, e) => Math.min(a, Date.parse(e.signedAt) || Date.now()), Date.now());
      const base = { payTo: account.address, priceAtomic: PRICE.toString(), settleMode: MODE,
        sales: entries.filter((e) => (e.status ?? 'settled') === 'settled').length,
        pending: pending.length, oldestPendingSeconds: pending.length ? Math.round((Date.now() - oldest) / 1000) : 0,
        uptimeSeconds: Math.round(process.uptime()), image: process.env.FLY_IMAGE_REF ?? null };
      try {
        return json(res, 200, { ok: true, chainId: CHAIN_ID, block: await blockNumber(),
          balance: formatUnits(await balanceOf(account.address), WIRE_DECIMALS), ...base });
      } catch (e) {
        return json(res, 503, { ok: false, chainId: CHAIN_ID, chainError: String(e.message).slice(0, 200), ...base });
      }
    }

    // A browser gets the page; anything else — curl, an agent, a crawler asking for JSON — gets the
    // same JSON as before, so nothing that already reads this endpoint breaks.
    if (u.pathname === '/' && /text\/html/.test(req.headers.accept ?? '') && !u.searchParams.has('json'))
      return serve('text/html; charset=utf-8', page(PUBLIC, PRICE_USDC, account.address), 300);
    if (u.pathname === '/' ) return json(res, 200, { service: 'poa-x402-notary',
      network: `eip155:${CHAIN_ID}`, payTo: account.address,
      tools: Object.entries(TOOLKIT).map(([name, t]) => ({ name, price: `${atomicToUsdc(t.price)} USDC per call`, http: `${PUBLIC}${t.path}`, about: t.blurb })),
      mcp: `${PUBLIC}/mcp`, llms: `${PUBLIC}/llms.txt`, source: 'https://github.com/xternal/poa-x402-seller',
      how: 'GET a paid URL, read PAYMENT-REQUIRED, sign TransferWithAuthorization, retry with PAYMENT-SIGNATURE.' });

    if (u.pathname === '/mcp') {
      if (req.method !== 'POST') return json(res, 405, { error: 'POST only' });
      let body = '';
      for await (const c of req) { body += c; if (body.length > MAX_BODY) return json(res, 413, { error: 'request too large' }); }
      let parsed; try { parsed = JSON.parse(body); } catch { return json(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); }
      return await mcp(req, res, parsed, resourceUrl);
    }

    const toolName = toolByPath[u.pathname];
    if (toolName) {
      const t = TOOLKIT[toolName];
      const r = await paidCall(toolName, t.args(u), req.headers['payment-signature'], resourceUrl);
      if (r.invalid) { log(`400 ${u.pathname} — ${r.invalid}`); return json(res, 400, { error: r.invalid, charged: false }); }
      if (r.gate) {
        const paid = r.gate;
        log(`402 ${u.pathname} — ${paid.reason}${paid.tx ? ' ' + paid.tx.slice(0, 18) + '…' : ''}`);
        // Receipts only for payment attempts whose signature checked out. A price check, garbage,
        // or an unsigned claim gets a 402 and a log line but no disk write: on a public server
        // anyone can send those, and a receipt per request would let them fill the volume the
        // ledger lives on — and a seller that can't write its ledger can't record a sale.
        if (paid.authenticated) await sellerReceipt(account, paid.pending ? 'pending' : 'refused', { tool: toolName, transport: 'http', resource: resourceUrl, priceAtomic: t.price.toString() },
          { served: false, reason: paid.reason, payer: paid.payer ?? null, tx: paid.tx ?? null });
        return challenge(res, resourceUrl, paid.reason, paid, toolName);
      }
      await sellerReceipt(account, 'sale', { tool: toolName, transport: 'http', resource: resourceUrl, priceAtomic: t.price.toString(), args: t.args(u) },
        { served: !r.out.error, replayed: !!r.paid.replayed, settlement: r.paid.settlement });
      res.writeHead(200, { 'content-type': 'application/json', 'PAYMENT-RESPONSE': encodeHeader(r.paid.settlement),
        'access-control-expose-headers': 'PAYMENT-RESPONSE', 'x-content-type-options': 'nosniff' });
      return res.end(JSON.stringify(r.out, null, 2));
    }
    json(res, 404, { error: 'not found' });
  } catch (e) {
    log('✗', e.message);
    json(res, 500, { error: e.message });
  }
});

// The process must outlive POA. The host wakes this machine on demand; if that lands in a POA
// deploy window (the write path was down ~1h on 20 Sep 2026), a crash here means a crash loop,
// a dark /livez, and pending settlements nobody can resolve. Chain calls at boot are
// informational; anything unexpected later is logged, not fatal — every request path already
// answers its own errors.
process.on('unhandledRejection', (e) => log('✗ unhandled', e?.message ?? e));

server.listen(PORT, async () => {
  log(`seller  ${account.address}`);
  try {
    log(`payTo   ${account.address}  balance ${formatUnits(await balanceOf(account.address), WIRE_DECIMALS)} USDC`);
    log(`price   ${PRICE} atomic = ${Number(PRICE) / 10 ** ATOMIC_DECIMALS} USDC · settle=${MODE} · chain ${CHAIN_ID} @ ${await blockNumber()}`);
  } catch (e) {
    log(`⚠ POA RPC unreachable at boot (${e.message}) — serving anyway; payments will answer 5xx/pending until it returns`);
  }
  const pending = Object.values(ledger).filter((e) => e.status === 'pending').length;
  if (pending) log(`⚠ ${pending} settlement(s) pending from before restart — resolved on the payer's next retry`);
  log(`listen  ${PUBLIC}  (GET /notarize?hash=0x… · POST /mcp)`);
});
