#!/usr/bin/env node
// Verify a notarization sold by seller.mjs — run by whoever received it.
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
// What it does NOT prove: that the hash means anything. Notarization dates a hash; it says
// nothing about what was hashed.

import { keccak256, toHex, recoverMessageAddress } from 'viem';
import { readFileSync } from 'node:fs';
import { stable, rpc, CHAIN_ID } from './seller-lib.mjs';

const src = process.argv[2];
const raw = src ? readFileSync(src, 'utf8') : await new Promise((r) => { let s = ''; process.stdin.on('data', (d) => (s += d)).on('end', () => r(s)); });
const { digest, serverSig, ...body } = JSON.parse(raw);

let bad = 0;
const check = (ok, name, detail) => { if (!ok) bad++; console.log(`  ${ok ? '✅' : '❌'} ${name}${detail ? `  (${detail})` : ''}`); };

console.log(`\nnotarization of ${body.hash}`);
console.log(`  notary ${body.notary} · chain ${body.chainId} · block ${body.poaBlock} · ${body.ts}\n`);

check(body.type === 'poa.notarization' && body.chainId === CHAIN_ID, 'well-formed for chain 77', `${body.type} / ${body.chainId}`);
check(keccak256(toHex(stable(body))) === digest, 'digest matches the canonical body');
const signer = await recoverMessageAddress({ message: { raw: digest }, signature: serverSig }).catch(() => null);
check(signer?.toLowerCase() === String(body.notary).toLowerCase(), 'serverSig recovers to the notary', signer ?? 'unrecoverable');
const block = await rpc('eth_getBlockByNumber', [toHex(BigInt(body.poaBlock)), false]);
check(block?.hash === body.poaBlockHash, 'block hash still matches chain 77', block?.hash ?? 'block not found');

console.log(`\n${bad ? `✗ ${bad} check(s) failed` : '✓ valid — this hash existed by POA block ' + body.poaBlock}\n`);
process.exit(bad ? 1 : 0);
