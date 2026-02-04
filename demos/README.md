# BalanceChain Live (Node + Explorer)

This repo contains:

1) **BalanceChain Node** (Cloudflare Worker + D1)
   - State-only (no blocks, no history, no consensus)
   - Stores only:
     - account registry (recovery key, active device key, reclaim nonce)
     - segment registry (latest owner state per (origin, segment_no))
   - Validates updates with:
     - **UTC ↔ counter match**
     - signature under **previous owner's active device key**
     - continuity (prev owner must match stored current)

2) **BalanceChain Explorer** (static HTML)
   - **Multi-node compare** (first node is primary; others cross-check)
   - **Serial lookup** across nodes
   - Shows account state: unlocked vs allowed-to-date vs remaining

---

## Deploy the Node (Cloudflare Workers + D1)

### 1) Install Wrangler

```bash
npm i -g wrangler
wrangler login
```

### 2) Create D1 and apply schema

```bash
wrangler d1 create balancechain_node
# copy database_id into wrangler.toml
wrangler d1 execute balancechain_node --file=./schema.sql
```

### 3) Set variables

Edit `wrangler.toml`:
- `GENESIS_UTC_MS` (your genesis UTC in ms)
- optional: `INITIAL_UNLOCKED`, `YEARLY_CAP`, `MAX_FUTURE_SKEW_MS`

### 4) Deploy

```bash
wrangler deploy
```

---

## Deploy the Explorer (Cloudflare Pages)

1) Create a new Pages project from this repo.
2) Set **Build command**: none
3) Set **Output directory**: `explorer`

Or just upload `explorer/index.html` to any static host.

In the UI:
- Paste multiple node URLs (one per line)
- Click **Load dashboard**
- Use **Serial Lookup** to query (origin, segment_no) across nodes

---

## API

### Node info
- `GET /v1/node/info`

### Explorer
- `GET /v1/explorer/stats`
- `GET /v1/explorer/accounts?limit=50&cursor=0`
- `GET /v1/explorer/accounts/{account_id}/summary`
- `GET /v1/explorer/serial?origin={origin_account_id}&no={segment_no}`

### Wallet minimal
- `GET /v1/accounts/{account_id}`
- `GET /v1/accounts/{account_id}/segments?role=current|origin&limit=500&cursor=0`
- `POST /v1/accounts/reclaim`
- `POST /v1/segments/apply`

---

## Security model (one line)

**Validity is deterministic (UTC/counter + signatures + continuity). Nodes are untrusted caches for availability.**
