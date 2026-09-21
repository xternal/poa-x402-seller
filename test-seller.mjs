#!/usr/bin/env node
// test-seller.mjs — can the paywall be walked past, and does a retry charge twice?
//
//   node --env-file=.env --env-file=.env.seller test-seller.mjs [base-url]
//
// Every attack below is free: a rejected payment moves nothing. The last two tests spend
// one real toll (0.001 USDC) to prove the honest path settles and that replaying the same
// authorization serves the same result again without a second charge.

import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';
import { bytesToHex, formatUnits } from 'viem';
import { randomBytes } from 'node:crypto';
import { CHAIN_ID, ASSET, WIRE_DECIMALS, balanceOf, decodeHeader } from './seller-lib.mjs';

const BASE = process.argv[2] ?? 'http://localhost:8402';
const RES = `${BASE}/notarize?hash=0x${'ab'.repeat(32)}`;
const payer = privateKeyToAccount(process.env.AGENT_PRIVATE_KEY);
const attacker = privateKeyToAccount(generatePrivateKey());
let pass = 0, fail = 0;

const quote = async () => {
  const r = await fetch(RES);
  return { status: r.status, pr: decodeHeader(r.headers.get('payment-required')) ?? JSON.parse(await r.text()) };
};
const { pr, status } = await quote();
const ACC = pr.accepts[0];

async function sign(signer, over = {}) {
  const now = Math.floor(Date.now() / 1000);
  const auth = { from: signer.address, to: ACC.payTo, value: BigInt(ACC.amount), validAfter: 0n,
    validBefore: BigInt(now + Number(ACC.maxTimeoutSeconds)), nonce: bytesToHex(randomBytes(32)), ...over };
  const signature = await signer.signTypedData({
    domain: { name: ACC.extra.name, version: ACC.extra.version, chainId: CHAIN_ID, verifyingContract: ASSET },
    types: { TransferWithAuthorization: [
      { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
      { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' }] },
    primaryType: 'TransferWithAuthorization', message: auth });
  return { signature, auth };
}
// `over` patches the SIGNED struct; `claim` patches only what we tell the seller we agreed to.
async function header(signer, over = {}, claim = {}, fromOverride) {
  const { signature, auth } = await sign(signer, over);
  const wire = { ...auth, from: fromOverride ?? auth.from, value: auth.value.toString(),
    validAfter: auth.validAfter.toString(), validBefore: auth.validBefore.toString() };
  return Buffer.from(JSON.stringify({ x402Version: 2, resource: pr.resource,
    accepted: { ...ACC, ...claim }, payload: { signature, authorization: wire } })).toString('base64');
}
async function hit(hdr, url = RES) {
  const r = await fetch(url, { headers: hdr ? { 'PAYMENT-SIGNATURE': hdr } : {} });
  const body = await r.json();
  const settle = decodeHeader(r.headers.get('payment-response'));
  return { status: r.status, reason: body?.error, body, settle };
}
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✅ ${name}${detail ? `  (${detail})` : ''}`); }
  else { fail++; console.log(`  ❌ ${name}  ${detail}`); }
}

console.log(`\ntarget ${BASE}  price ${ACC.amount} atomic → ${ACC.payTo}`);
const before = await balanceOf(ACC.payTo);
console.log(`seller balance ${formatUnits(before, WIRE_DECIMALS)} USDC\n`);

console.log('quoting');
check('unpaid GET returns 402 with a quote', status === 402 && !!ACC.payTo, `status ${status}`);
check('quote is x402 v2 exact/eip155:77', pr.x402Version === 2 && ACC.scheme === 'exact' && ACC.network === `eip155:${CHAIN_ID}`);
check('quote names the seller, not the demo collector',
  ACC.payTo.toLowerCase() !== '0x867c4171576f7a4d2557c4a80694306837a880aa', ACC.payTo);
check('resource.url is the public URL, not an internal origin', ACC && pr.resource.url.startsWith(BASE), pr.resource.url);

console.log('\nwalking past the paywall');
check('no header → 402', (await hit()).status === 402);
check('garbage header → 402 invalid_payload', (await hit('not-base64-at-all')).reason === 'invalid_payload');
check('empty envelope → 402', (await hit(Buffer.from('{}').toString('base64'))).status === 402);
{ const r = await hit(await header(payer, { to: attacker.address }, { payTo: attacker.address }));
  check('pay someone else, claim they are the seller → recipient_mismatch', r.reason === 'recipient_mismatch', r.reason); }
{ const r = await hit(await header(payer, { value: 1n }, { amount: '1' }));
  check('underpay 1 atomic, claim the price is 1 → value_mismatch', r.reason === 'authorization_value_mismatch', r.reason); }
{ const r = await hit(await header(payer, { value: BigInt(ACC.amount) * 2n }));
  check('overpay is not accepted as "close enough" → value_mismatch', r.reason === 'authorization_value_mismatch', r.reason); }
{ const now = Math.floor(Date.now() / 1000);
  const r = await hit(await header(payer, { validBefore: BigInt(now - 10) }));
  check('expired authorization → authorization_valid_before', r.reason === 'authorization_valid_before', r.reason); }
{ const now = Math.floor(Date.now() / 1000);
  const r = await hit(await header(payer, { validAfter: BigInt(now + 600) }));
  check('not-yet-valid authorization → authorization_valid_after', r.reason === 'authorization_valid_after', r.reason); }
{ const r = await hit(await header(payer, { validBefore: 99999999999n }));
  check('never-expiring authorization capped (SECURITY-NOTES N1) → window_too_long',
    r.reason === 'authorization_window_too_long', r.reason); }
{ const r = await hit(await header(attacker, {}, {}, payer.address));
  check('forged: attacker signs, claims from=payer → invalid_signature', r.reason === 'invalid_signature', r.reason); }
{ const r = await hit(await header(attacker));
  check('signed by an empty account → insufficient_funds, nothing broadcast', r.reason === 'insufficient_funds', r.reason); }

const mid = await balanceOf(ACC.payTo);
check('no rejected attempt moved money', mid === before, `${formatUnits(mid - before, WIRE_DECIMALS)} USDC`);

console.log('\nhonest payment (spends one toll)');
const hdr = await header(payer);
const r1 = await hit(hdr);
check('valid payment → 200 and the tool runs', r1.status === 200 && !!r1.body?.serverSig, `${r1.status} block ${r1.body?.poaBlock}`);
check('PAYMENT-RESPONSE carries the settlement tx', !!r1.settle?.transaction, r1.settle?.transaction);
check('settled by self-settle, not the hosted facilitator', r1.settle?.path === 'self-settle', r1.settle?.path);
await new Promise((r) => setTimeout(r, 2500));
const afterPay = await balanceOf(ACC.payTo);
check('seller balance went UP by the toll', afterPay - before === 10n ** BigInt(WIRE_DECIMALS - 6) * BigInt(ACC.amount),
  `+${formatUnits(afterPay - before, WIRE_DECIMALS)} USDC`);

console.log('\nretry (x402 tells clients to resend the same header after a 5xx)');
const r2 = await hit(hdr);
check('same authorization + same request → 200 with the identical artifact',
  r2.status === 200 && r2.body?.digest === r1.body?.digest, r2.body?.digest ?? r2.reason);
await new Promise((r) => setTimeout(r, 2500));
const afterReplay = await balanceOf(ACC.payTo);
check('retry did NOT charge a second time', afterReplay === afterPay, `${formatUnits(afterReplay - afterPay, WIRE_DECIMALS)} USDC`);

// One toll buys one call. Reusing a settled authorization for a different argument would
// otherwise be unlimited free calls — the precompile cannot catch this, only the seller can.
const r3 = await hit(hdr, `${BASE}/notarize?hash=0x${'cd'.repeat(32)}`);
check('same authorization, DIFFERENT argument → refused (authorization_already_used)',
  r3.status === 402 && r3.reason === 'authorization_already_used', `${r3.status} ${r3.reason}`);

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
