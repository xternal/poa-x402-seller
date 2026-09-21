# poa-x402-seller

A **paid tool server** on POA chain 77 (`eip155:77`). Every call costs a toll in native USDC,
paid with [x402](https://x402.org): no accounts, no API keys — the payment *is* the
authentication. Reachable as plain HTTP and as an **MCP tool** over Streamable HTTP, so an agent
(Claude, Cursor, anything that can sign EIP-3009) can call it and pay per call.

One tool, deliberately trivial so the payment loop is the point:

**`notarize(hash)`** → `{hash, poaBlock, poaBlockHash, ts, digest, serverSig}` — proof that the
hash existed by that POA block, signed by the notary key. Check one with
`node verify-notarization.mjs proof.json` (digest, signature, and the block hash against the chain).

## It settles for itself

POA's hosted x402 facilitator only settles for its own demo resource — it ignores the payTo and
price you send it and binds against its own. But the settlement precompile
`0x2d00000000000000000000000000000000000006` accepts a `transferWithAuthorization` from **any**
caller, including an account with a zero balance. So this server submits the payer's signed
authorization itself:

```
client ──GET /notarize──▶ seller ──402 + quote (our payTo, our price)──▶ client
client ──GET + PAYMENT-SIGNATURE──▶ seller ── checks, then transferWithAuthorization ──▶ 0x2d…0006
                                    seller ◀── receipt status 0x1 ── then serves the result
```

The entire dependency list for selling on this chain is one key and an RPC URL. A brand-new key
with no balance collects its first payment.

## Run it

```bash
npm install
npm run keygen                                   # writes .env.seller (0600) + seller.address
node --env-file=.env.seller seller.mjs           # :8402
node --env-file=/path/to/payer.env test-seller.mjs http://localhost:8402   # needs AGENT_PRIVATE_KEY; spends 0.001
```

| endpoint | cost | |
|---|---|---|
| `GET /` | free | what this is, what it costs |
| `GET /livez` | free | liveness, no chain calls |
| `GET /health` | free | chain height, payTo, balance, sales |
| `GET /notarize?hash=0x…` | **paid** | 402 until a `PAYMENT-SIGNATURE` settles |
| `POST /mcp` | `tools/call` **paid** | MCP (JSON-RPC over HTTP); `initialize`, `tools/list` free |

## What it guarantees

- **Binds the signature, not the client's claim.** The signed authorization's recipient, amount
  and window are checked against the quote *this server* issued. The `accepted` block a client
  echoes back is ignored as evidence.
- **Verifies the EIP-712 signature locally** — POA's `/verify` can't vet a third party's quote.
- **One authorization buys exactly one call.** A retry with the same request replays the identical
  artifact at no charge; the same authorization with a different argument is refused
  (`authorization_already_used`). Without this, one toll buys unlimited calls.
- **A lost response never means paid-but-not-served.** The settle tx is signed, its hash computed
  locally and written down *before* it's broadcast. If the RPC drops mid-settlement the server
  answers `402 settlement_pending` (with the tx hash and `Retry-After`) and on retry resends that
  same signed tx — it can land at most once.
- **Doesn't amplify load onto POA's RPC.** Per-client rate limit (default 60/min), 64 KB body cap.
- Rejects authorizations valid for longer than the quote allows (POA itself doesn't cap this).
- Every sale, refusal and pending settlement is a signed receipt (`seller-receipts.jsonl`).

## Deploy on Fly.io

```bash
brew install flyctl && fly auth login
fly apps create poa-x402-seller --org personal         # app names are global: if taken, change `app` in fly.toml
fly volumes create seller_data --region lhr --size 1 --yes
grep '^SELLER_PRIVATE_KEY=' .env.fly | fly secrets import   # key never touches argv or shell history
fly deploy --ha=false                                   # exactly one machine — see below
curl https://poa-x402-seller.fly.dev/health
```

Generate the hosted key with `SELLER_ENV_FILE=.env.fly npm run keygen`, and keep a copy
somewhere safe: Fly secrets are write-only, so the laptop file is the only way to ever recover
the key — and the key is the only way to move what the seller earns.

**Exactly one machine.** The ledger that makes retries safe is a file on the machine's volume.
Two machines would have two ledgers; the chain would still stop a double *debit*, but a retry
landing on the other machine would be refused instead of served. Idle machines stop and wake on
the next request (`auto_stop_machines`), and the ledger survives the restart.

## Config

| env | default | |
|---|---|---|
| `SELLER_PRIVATE_KEY` | — | required; receives payments and signs notarizations |
| `SELLER_PRICE_ATOMIC` | `1000` | 6-decimal atomic units: 1000 = 0.001 USDC |
| `SELLER_MAX_TIMEOUT` | `180` | longest authorization window accepted, seconds |
| `SELLER_PUBLIC_URL` | `https://$FLY_APP_NAME.fly.dev`, else `http://localhost:$PORT` | quoted in `resource.url` |
| `SELLER_PORT` | `8402` (`8080` in the image) | |
| `SELLER_LEDGER` / `SELLER_RECEIPTS_FILE` | `seller-ledger.json` / `seller-receipts.jsonl` | put both on persistent storage |
| `SELLER_RATE_PER_MIN` | `60` | per client |
| `SELLER_TRUST_PROXY` | — | `fly` to rate-limit by `Fly-Client-IP` |
| `SELLER_SETTLE_MODE` | `self` | `facilitator` only works for POA's own demo payTo |

## Known limits

- **Settlement status is knowable only by tx hash.** POA's public RPC has no `eth_getLogs` and no
  `eth_call`, so the server can't ask "was this authorization consumed, and by whom?" If someone
  front-runs a payer's authorization (EIP-3009 is a bearer instrument), our settle reverts while
  the money still arrives — and the server can't see it was paid. Only possible if a header leaks.
- **A settled authorization is public** (it's in the settle tx's calldata). Until it expires, anyone
  who also knows the exact request can fetch the cached result. Harmless for `notarize`; a tool that
  sells data should cache briefly or not at all.
- Settlements run one at a time (on POA a failed tx doesn't consume its nonce, so concurrent settles
  can strand each other). Fine at this scale.

## Chain facts this relies on (verified live, Sep 2026)

- x402 v2 payloads need top-level `resource` **and** `accepted`; header is `PAYMENT-SIGNATURE` (base64).
- EIP-712 domain `USDC` / `2` / chainId 77 / verifyingContract `0x2d…0006`.
- Quote `amount` is 6-decimal atomic; `eth_getBalance` is 18-decimal. The precompile scales between
  them itself — never take decimals from a quote.
- Gasless (`eth_gasPrice` = 0), 2 s blocks, final when produced.
