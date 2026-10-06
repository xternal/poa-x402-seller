#!/usr/bin/env node
// Verify what seller.mjs sold you — a notarization or a fetch attestation — as the recipient.
//
//   node verify-notarization.mjs proof.json
//   node agent-mcp.mjs | sed -n '/^{/,/^}/p' | node verify-notarization.mjs
//
// Three independent checks:
//   1. the digest is the keccak of the artifact's own canonical body (nothing was edited),
//   2. serverSig recovers to the notary named inside it (nobody else could have issued it),
//   3. poaBlockHash is still what chain 77 says that block hash is (the anchor is real, and
//      the notary could not have known it before that block was produced).
//
// What it does NOT prove: for a notarization, that the hash means anything — it dates a hash and
// says nothing about what was hashed. For a fetch attestation, that the page was telling the truth:
// it says this server fetched that URL and got this body, by this block. The text extract and the
// sha256 of the full body are both inside the signature.

import { keccak256, toHex, recoverMessageAddress } from 'viem';
import { readFileSync } from 'node:fs';
import { stable, rpc, CHAIN_ID } from './seller-lib.mjs';

const src = process.argv[2];
const raw = src ? readFileSync(src, 'utf8') : await new Promise((r) => { let s = ''; process.stdin.on('data', (d) => (s += d)).on('end', () => r(s)); });
// `payment` is not part of what the notary signed: it's the record a paying wallet (wallet-mcp)
// attaches to the result it hands its model. Set aside, like digest and serverSig.
const { digest, serverSig, payment, ...body } = JSON.parse(raw);
void payment;

const KINDS = { 'poa.notarization': 'hash anchored to a block', 'poa.fetch-attestation': 'what a URL said, anchored to a block' };
let bad = 0;
const check = (ok, name, detail) => { if (!ok) bad++; console.log(`  ${ok ? '✅' : '❌'} ${name}${detail ? `  (${detail})` : ''}`); };

console.log(`\n${KINDS[body.type] ?? body.type}: ${body.hash ?? body.finalUrl ?? body.url}`);
console.log(`  notary ${body.notary} · chain ${body.chainId} · block ${body.poaBlock} · ${body.ts}`);
if (body.type === 'poa.fetch-attestation')
  console.log(`  http ${body.httpStatus} · ${body.contentType ?? 'no content-type'} · ${body.bytes} bytes${body.truncated ? ' (truncated)' : ''} · body sha256 ${body.sha256}`);
console.log();

check(!!KINDS[body.type] && body.chainId === CHAIN_ID, 'well-formed for chain 77', `${body.type} / ${body.chainId}`);
check(keccak256(toHex(stable(body))) === digest, 'digest matches the canonical body');
const signer = await recoverMessageAddress({ message: { raw: digest }, signature: serverSig }).catch(() => null);
check(signer?.toLowerCase() === String(body.notary).toLowerCase(), 'serverSig recovers to the notary', signer ?? 'unrecoverable');
const block = await rpc('eth_getBlockByNumber', [toHex(BigInt(body.poaBlock)), false]);
check(block?.hash === body.poaBlockHash, 'block hash still matches chain 77', block?.hash ?? 'block not found');

const claim = body.type === 'poa.fetch-attestation'
  ? `✓ valid — ${body.finalUrl} answered HTTP ${body.httpStatus} with this body by POA block ${body.poaBlock}`
  : `✓ valid — this hash existed by POA block ${body.poaBlock}`;
console.log(`\n${bad ? `✗ ${bad} check(s) failed` : claim}\n`);
process.exit(bad ? 1 : 0);
