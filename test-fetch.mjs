#!/usr/bin/env node
// test-fetch.mjs — premium_fetch: can it be turned into an open proxy, and does it charge fairly?
//
//   node --env-file=/path/to/payer.env test-fetch.mjs [base-url]
//
// The blocked-URL checks are free by design: an unusable request is refused before payment, so a
// buyer never pays for an answer the server was never going to give. One real fetch is paid for
// (0.002 USDC) and the attestation it returns is verified against the chain.

import { spawn } from 'node:child_process';
import { privateKeyToAccount } from 'viem/accounts';
import { bytesToHex, formatUnits } from 'viem';
import { randomBytes } from 'node:crypto';
import { CHAIN_ID, ASSET, WIRE_DECIMALS, balanceOf, decodeHeader } from './seller-lib.mjs';

const BASE = (process.argv[2] ?? 'http://localhost:8402').replace(/\/$/, '');
const payer = privateKeyToAccount(process.env.AGENT_PRIVATE_KEY ?? process.env.PAYER_PRIVATE_KEY);
let pass = 0, fail = 0;
const check = (name, cond, detail) => { cond ? pass++ : fail++; console.log(`  ${cond ? '✅' : '❌'} ${name}${detail !== undefined ? `  (${String(detail).slice(0, 120)})` : ''}`); };
const get = (path, hdr) => fetch(BASE + path, { headers: hdr ? { 'PAYMENT-SIGNATURE': hdr } : {} });
const fetchUrl = (target) => `/fetch?url=${encodeURIComponent(target)}`;

async function quote(path) {
  const r = await get(path);
  return { status: r.status, body: await r.json().catch(() => null), pr: decodeHeader(r.headers.get('payment-required')) };
}
async function sign(acc, pr) {
  const now = Math.floor(Date.now() / 1000);
  const auth = { from: payer.address, to: acc.payTo, value: BigInt(acc.amount), validAfter: 0n,
    validBefore: BigInt(now + Number(acc.maxTimeoutSeconds)), nonce: bytesToHex(randomBytes(32)) };
  const signature = await payer.signTypedData({
    domain: { name: 'USDC', version: '2', chainId: CHAIN_ID, verifyingContract: ASSET },
    types: { TransferWithAuthorization: [{ name: 'from', type: 'address' }, { name: 'to', type: 'address' },
      { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
      { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] },
    primaryType: 'TransferWithAuthorization', message: auth });
  return Buffer.from(JSON.stringify({ x402Version: 2, resource: pr.resource, accepted: acc, payload: { signature,
    authorization: { ...auth, value: auth.value.toString(), validAfter: '0', validBefore: auth.validBefore.toString() } } })).toString('base64');
}

const S0 = await balanceOf((await quote(fetchUrl('https://example.com'))).pr.accepts[0].payTo);
console.log(`\ntarget ${BASE}  ·  seller balance ${formatUnits(S0, WIRE_DECIMALS)} USDC\n`);

console.log('the quote');
const q = await quote(fetchUrl('https://example.com'));
const acc = q.pr.accepts[0];
check('unpaid fetch returns 402 with its own price', q.status === 402 && acc.amount === '2000', `${q.status} · ${acc.amount} atomic`);
check('priced above notarize', BigInt(acc.amount) > BigInt((await quote('/notarize?hash=0x' + 'ab'.repeat(32))).pr.accepts[0].amount));

console.log('\nit cannot be turned into a proxy — and refusing is free');
for (const [name, target, want] of [
  ['localhost', 'http://localhost/', /not allowed/],
  ['loopback IP', 'http://127.0.0.1/', /private address/],
  ['cloud metadata', 'http://169.254.169.254/latest/meta-data/', /private address/],
  ['private range', 'http://10.0.0.1/', /private address/],
  ['file scheme', 'file:///etc/passwd', /scheme/],
  ['credentials in URL', 'http://user:pass@example.com/', /credentials/],
  ['odd port', 'http://example.com:22/', /port/],
  ['unresolvable host', 'http://nope.invalid/', /not allowed|cannot resolve/],
  ['not a URL', 'ht!tp:/example', /not a URL|scheme/],
]) {
  const r = await get(fetchUrl(target));
  const b = await r.json().catch(() => ({}));
  check(`${name} → refused, not charged`, r.status === 400 && want.test(b.error ?? '') && b.charged === false, `${r.status} ${b.error ?? ''}`);
}
{ const r = await get('/fetch?url=https://example.com&maxChars=9');
  check('silly maxChars → refused, not charged', r.status === 400 && (await r.json()).charged === false); }
{ const r = await get(fetchUrl('https://www.google.com/search?q=x'));
  const b = await r.json().catch(() => ({}));
  check('a path robots.txt disallows → refused, not charged', r.status === 400 && /robots/.test(b.error ?? ''), b.error); }
check('none of that moved money', (await balanceOf(acc.payTo)) === S0);

console.log('\none real fetch (0.002 USDC)');
const hdr = await sign(acc, q.pr);
const r1 = await get(fetchUrl('https://example.com'), hdr);
const art = await r1.json();
check('200 and a signed attestation', r1.status === 200 && !!art.serverSig && art.type === 'poa.fetch-attestation', `${r1.status} ${art.type ?? art.error}`);
check('it says what the page answered', art.httpStatus === 200 && /example/i.test(art.text ?? ''), `http ${art.httpStatus} · ${art.bytes} bytes · ${art.contentType}`);
check('and hashes the whole body, not just the extract', /^0x[0-9a-f]{64}$/.test(art.sha256 ?? ''), art.sha256);
check('anchored to a block', Number(art.poaBlock) > 0 && /^0x[0-9a-f]{64}$/.test(art.poaBlockHash ?? ''), `block ${art.poaBlock}`);
const settle = decodeHeader(r1.headers.get('payment-response'));
check('settled by self-settle', settle?.path === 'self-settle', settle?.transaction);
await new Promise((r) => setTimeout(r, 3000));
const S1 = await balanceOf(acc.payTo);
check('seller +exactly the fetch price', S1 - S0 === BigInt(acc.amount) * 10n ** 12n, `+${formatUnits(S1 - S0, WIRE_DECIMALS)}`);

console.log('\nthe payment buys that one fetch');
const r2 = await get(fetchUrl('https://example.com'), hdr);
const art2 = await r2.json();
check('same authorisation, same URL → same artifact, no second charge', r2.status === 200 && art2.digest === art.digest);
const r3 = await get(fetchUrl('https://example.org'), hdr);
check('same authorisation, different URL → refused', r3.status === 402 && (await r3.json()).error === 'authorization_already_used');
await new Promise((r) => setTimeout(r, 2500));
check('still only one charge', (await balanceOf(acc.payTo)) === S1);

console.log('\nthe buyer can verify what they bought');
const v = await new Promise((resolve) => { const p = spawn(process.execPath, ['verify-notarization.mjs']); let o = '';
  p.stdout.on('data', (x) => (o += x)); p.on('close', (code) => resolve({ code, o })); p.stdin.end(JSON.stringify(art)); });
check('verify-notarization accepts the attestation', v.code === 0, v.o.trim().split('\n').at(-1));

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
