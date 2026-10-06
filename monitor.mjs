#!/usr/bin/env node
// monitor.mjs — is the public seller up, honest, and able to settle? Free: it never pays.
//
//   node monitor.mjs [https://poa-x402-seller.fly.dev]
//
// Run every few hours by .github/workflows/monitor.yml; a failing check fails the job and GitHub
// emails the repo owner. It checks what a customer would see, not just that a port is open:
// the quote must name OUR payTo at OUR price on POA's asset, or someone has changed what this
// seller charges or who it pays. POA's own availability is checked separately and named as such,
// because a POA deploy window is not our outage — but it still means nobody can pay us.

import { readFileSync } from 'node:fs';

const BASE = (process.argv[2] ?? process.env.SELLER_URL ?? 'https://poa-x402-seller.fly.dev').replace(/\/$/, '');
const PAY_TO = (process.env.EXPECT_PAY_TO ?? readFileSync(new URL('./seller.address', import.meta.url), 'utf8')).trim().toLowerCase();
const PRICE = process.env.EXPECT_PRICE_ATOMIC ?? '1000';
const RPC = process.env.POA_RPC ?? 'https://rpc.poa.net';
const ASSET = '0x2d00000000000000000000000000000000000006';

const results = [];
async function check(name, fn) {
  const t0 = Date.now();
  try { const detail = await fn(); results.push({ ok: true, name, detail, ms: Date.now() - t0 }); }
  catch (e) { results.push({ ok: false, name, detail: e.message, ms: Date.now() - t0 }); }
}
const must = (cond, msg) => { if (!cond) throw new Error(msg); };
// An auto-stopped machine takes a few seconds to wake on the first request.
const get = (path, init) => fetch(BASE + path, { signal: AbortSignal.timeout(30_000), ...init });
const rpc = async (method, params = []) => {
  const r = await fetch(RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(15_000),
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`); return j.result;
};

await check('POA chain is producing blocks', async () => {
  must(Number(await rpc('eth_chainId')) === 77, 'eth_chainId is not 77');
  const a = Number(await rpc('eth_blockNumber'));
  await new Promise((r) => setTimeout(r, 5000));
  const b = Number(await rpc('eth_blockNumber'));
  must(b > a, `no new block in 5s (stuck at ${a}) — POA is down or halted; nobody can pay anyone`);
  return `block ${b}`;
});

await check('seller process is up (/livez)', async () => {
  const r = await get('/livez'); must(r.ok, `HTTP ${r.status}`); return `HTTP ${r.status}`;
});

let health;
await check('seller can reach POA and holds nothing stuck (/health)', async () => {
  const r = await get('/health'); health = await r.json();
  must(health.chainError === undefined, `seller cannot reach POA RPC: ${health.chainError}`);
  must(health.ok === true && health.chainId === 77, `health not ok: ${JSON.stringify(health).slice(0, 160)}`);
  must(String(health.payTo).toLowerCase() === PAY_TO, `payTo is ${health.payTo}, expected ${PAY_TO} — key changed?`);
  must(health.pending === 0 || health.oldestPendingSeconds < 600,
    `${health.pending} settlement(s) pending for ${health.oldestPendingSeconds}s — see RUNBOOK "stuck pending"`);
  return `${health.sales} sales · ${health.balance} USDC · ${health.pending} pending · up ${health.uptimeSeconds}s`;
});

await check('unpaid call gets an honest quote (HTTP 402)', async () => {
  const r = await get(`/notarize?hash=0x${'00'.repeat(32)}`);
  must(r.status === 402, `expected 402, got ${r.status}`);
  const pr = JSON.parse(Buffer.from(r.headers.get('payment-required') ?? '', 'base64').toString());
  const a = pr.accepts?.[0] ?? {};
  must(a.network === 'eip155:77' && a.scheme === 'exact', `wrong network/scheme ${a.scheme}@${a.network}`);
  must(String(a.asset).toLowerCase() === ASSET, `wrong asset ${a.asset}`);
  must(String(a.payTo).toLowerCase() === PAY_TO, `quote pays ${a.payTo}, expected ${PAY_TO}`);
  must(a.amount === PRICE && a.extra?.decimals === 6, `quote asks ${a.amount} @ ${a.extra?.decimals} decimals, expected ${PRICE} @ 6`);
  must(String(pr.resource?.url).startsWith(BASE), `resource.url ${pr.resource?.url} is not ${BASE}`);
  return `${a.amount} atomic → ${a.payTo.slice(0, 10)}…`;
});

await check('the fetch tool quotes its own price, and refuses a private URL for free', async () => {
  const q = await get(`/fetch?url=${encodeURIComponent('https://example.com')}`);
  must(q.status === 402, `expected 402, got ${q.status}`);
  const a = JSON.parse(Buffer.from(q.headers.get('payment-required') ?? '', 'base64').toString()).accepts?.[0] ?? {};
  must(a.amount === (process.env.EXPECT_FETCH_PRICE_ATOMIC ?? '2000'), `fetch quote is ${a.amount}, expected ${process.env.EXPECT_FETCH_PRICE_ATOMIC ?? '2000'}`);
  // The guard that keeps a paid fetcher from becoming an open proxy, checked from outside.
  const blocked = await get(`/fetch?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}`);
  const body = await blocked.json().catch(() => ({}));
  must(blocked.status === 400 && body.charged === false, `metadata URL answered ${blocked.status} ${JSON.stringify(body).slice(0, 80)}`);
  return `${a.amount} atomic · private URL refused with ${blocked.status}, not charged`;
});

await check('MCP endpoint lists the paid tool', async () => {
  const r = await get('/mcp', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }) });
  const tools = (await r.json()).result?.tools?.map((t) => t.name) ?? [];
  must(tools.includes('notarize') && tools.includes('premium_fetch'), `tools/list returned ${JSON.stringify(tools)}`);
  return tools.join(', ');
});

for (const r of results) console.log(`${r.ok ? '✅' : '❌'} ${r.name}  —  ${r.detail}  (${r.ms}ms)`);
const failed = results.filter((r) => !r.ok);
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFileSync } = await import('node:fs');
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### ${failed.length ? '❌' : '✅'} ${BASE}\n\n` +
    results.map((r) => `- ${r.ok ? '✅' : '❌'} **${r.name}** — ${r.detail}`).join('\n') + '\n');
}
console.log(failed.length ? `\n${failed.length} check(s) failed` : '\nall good');
process.exit(failed.length ? 1 : 0);
