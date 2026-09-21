#!/usr/bin/env node
// Mint the seller's identity. It only ever RECEIVES, so it needs no balance — and on this
// chain it does not need one to collect either: the precompile accepts a call from an empty
// account (SECURITY-NOTES N6). Never reuse the payer key in .env; the point of a seller is
// that it is a different party.
//
//   node seller-keygen.mjs
//
// Writes .env.seller (0600, gitignored) and seller.address. Refuses to overwrite.
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { existsSync, writeFileSync } from 'node:fs';

const OUT = process.env.SELLER_ENV_FILE ?? '.env.seller';
if (existsSync(OUT)) { console.error(`✗ ${OUT} already exists — delete it first if you really mean to rotate the seller key`); process.exit(1); }

const pk = generatePrivateKey();
const account = privateKeyToAccount(pk);
writeFileSync(OUT, [
  '# Seller identity — receives only, needs no balance. Never the payer key.',
  `SELLER_PRIVATE_KEY=${pk}`,
  `SELLER_PAY_TO=${account.address}`,
  '',
  '# Price in 6-decimal atomic units, as x402 quotes them. 1000 = 0.001 USDC.',
  'SELLER_PRICE_ATOMIC=1000',
  '# Authorization window we will accept, seconds. Longer than this is refused (N1).',
  'SELLER_MAX_TIMEOUT=180',
  '# self | facilitator. POA\'s hosted facilitator cannot settle a third-party payTo (S1).',
  'SELLER_SETTLE_MODE=self',
  'SELLER_PORT=8402',
  '# The URL clients actually reach, quoted in resource.url instead of an internal origin (B6).',
  'SELLER_PUBLIC_URL=http://localhost:8402',
  '',
].join('\n'), { mode: 0o600 });
writeFileSync('seller.address', account.address + '\n');
console.log(`seller payTo ${account.address}\nwrote ${OUT} (0600) and seller.address`);
