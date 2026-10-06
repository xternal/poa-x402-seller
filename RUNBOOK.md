# RUNBOOK — poa-x402-seller in production

| | |
|---|---|
| Live | https://poa-x402-seller.fly.dev |
| Fly | app `poa-x402-seller` · org `personal` · region `lhr` · **one** machine · volume `seller_data` → `/data` |
| payTo | `0xdC6C7F3dcEC8Ac75d3656bfD697a693acEB38244` (`seller.address`) |
| Key | Fly secret `SELLER_PRIVATE_KEY` (write-only) · local `.env.fly` (gitignored) · one backup outside the repo |
| Monitor | `.github/workflows/monitor.yml`, every 3 h — a failure emails you |
| Durable record | `/data/seller-ledger.json`, `/data/seller-receipts.jsonl` · volume snapshots daily, kept 14 days |

## Is it OK?

```bash
node monitor.mjs                                  # what a customer sees; free, never pays
fly status -a poa-x402-seller                     # machine started/stopped (stopped when idle is normal)
fly logs -a poa-x402-seller                       # 💰 = a sale, ⚠ = POA unreachable / pending at boot
curl -s https://poa-x402-seller.fly.dev/health    # sales, balance, pending, image
```

`stopped` in `fly status` is fine — the machine sleeps when idle and wakes on the next request
(first call takes a few seconds). Monitor runs: `gh run list -R xternal/poa-x402-seller -w monitor`.

## Change and deploy

This repo is the source of truth for the seller. `poa-agent` keeps byte-identical copies for its
wallet tests — copy them over after any change.

```bash
node --env-file=.env.fly seller.mjs 8402 &                                   # 1. run locally
node --env-file=../poa/.env test-seller.mjs http://localhost:8402            # 2. 23 checks, spends 0.001
fly deploy --ha=false --local-only                                           # 3. build on this Mac, ship
node monitor.mjs                                                             # 4. confirm
for f in seller.mjs seller-lib.mjs seller-keygen.mjs verify-notarization.mjs test-seller.mjs; do cp $f ../poa/; done
```

**Roll back:** `fly releases -a poa-x402-seller --image`, then
`fly deploy --ha=false --image registry.fly.io/poa-x402-seller:<previous tag>`.

**Dependabot** opens monthly PRs (npm, Docker base image, Actions). Merge, then deploy as above.

## Never

- **Never run two machines.** The ledger is a file on one volume; a second machine would have its own
  and serve retries inconsistently. If `fly status` ever shows two: `fly scale count 1 -a poa-x402-seller`.
- Never commit `.env.fly` or print the key. Fly secrets can't be read back — the laptop file and its
  backup are the only copies, and the key is the only way to move what the seller has earned.

## Receipts and ledger

```bash
fly ssh sftp get /data/seller-receipts.jsonl ./fly-receipts.jsonl -a poa-x402-seller
fly ssh sftp get /data/seller-ledger.json    ./fly-ledger.json    -a poa-x402-seller
node ../poa/verify.mjs fly-receipts.jsonl                    # every receipt's hash + signature
fly volumes snapshots list <volume id> -a poa-x402-seller   # id from: fly volumes list
```

**Restoring a snapshot** brings back an older ledger. Payments settled after the snapshot are still
on-chain (the money is ours), but the seller no longer remembers them: a client retrying one of those
would get `settle_failed` instead of its result. After a restore, compare recent `💰` log lines
against the restored ledger.

## Incidents

**POA is down / deploying** (monitor: *POA chain is producing blocks* fails; `/health` → 503 with
`chainError`). Not our outage, nothing to fix — the seller keeps serving quotes, paid calls answer
5xx or `settlement_pending`, clients resend the same header. **Don't restart the machine**: it
already survives this, and a restart gains nothing.

**Stuck pending** (`/health` `pending > 0` for more than 10 minutes). A settle tx was broadcast and
the payer never came back to collect. Find it in the ledger (`status: pending`, `tx`) and look it
up: `https://poa.net/77/tx/<tx>`. Mined `0x1` → we were paid; the next retry of that header will
serve it — if the payer is someone you know, tell them to resend. No receipt and the authorization's
`validBefore` has passed → it can never land; nothing was paid.

**A site complains about our fetcher.** Our user agent identifies us and links `/llms.txt`, so
complaints should arrive rather than silent blocks. `premium_fetch` already honours `robots.txt` for
our agent and never follows a redirect into a private address. To exclude a host entirely, add it to
`BLOCKED_HOST` in `seller.mjs` and deploy; to slow the fetcher down, lower `SELLER_RATE_PER_MIN`. If
someone is paying to aim us at a target, every call is in `seller-receipts.jsonl` with the URL — that
is the audit trail to answer with.

**Rate-limit complaints.** Raise `SELLER_RATE_PER_MIN` in `fly.toml`, deploy. It exists to stop the
seller being used to flood POA's public RPC; keep it finite.

**Key compromise suspected.** `SELLER_ENV_FILE=.env.fly.new npm run keygen` → move the balance off the
old payTo (native transfer signed by the old key) → `grep '^SELLER_PRIVATE_KEY=' .env.fly.new | fly
secrets import` → `fly deploy --ha=false` → update `seller.address` (the monitor checks it) → tell
anyone whose mandate allowlists the old payTo.

## Costs (Sep 2026, approximate — fly.io/pricing is authoritative)

1 GB volume ≈ $0.15/month · compute ≈ $0 idle (auto-stop), ≈ $2/month if it ever runs non-stop ·
shared IPv4 free · snapshots: tiny (the data is kilobytes) · GitHub Actions ≈ 240 min/month of the
free private-repo allowance.
