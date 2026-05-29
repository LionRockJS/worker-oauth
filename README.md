# worker-oauth

OAuth 2.1 authorization server running on Cloudflare Workers, backed by D1 (SQLite) and KV.

## Deploy

### Prerequisites

- [Node.js](https://nodejs.org) ≥ 18
- [Wrangler](https://developers.cloudflare.com/workers/wrangler/) v3 — `npm install -g wrangler`
- A Cloudflare account authenticated with `wrangler login`

---

### 1. Install dependencies

```sh
npm install
```

---

### 2. Create the D1 database

```sh
wrangler d1 create worker-oauth-db
```

Copy the `database_id` from the output and update `wrangler.jsonc`:

```jsonc
"d1_databases": [
  {
    "binding": "DB",
    "database_name": "worker-oauth-db",
    "database_id": "<paste-your-id-here>",
    "migrations_dir": "migrations"
  }
]
```

---

### 3. Create the KV namespaces

```sh
wrangler kv namespace create SESSIONS
wrangler kv namespace create OAUTH_KV
```

Copy each `id` from the output into `wrangler.jsonc`:

```jsonc
"kv_namespaces": [
  { "binding": "SESSIONS", "id": "<sessions-namespace-id>" },
  { "binding": "OAUTH_KV", "id": "<oauth-kv-namespace-id>" }
]
```

---

### 4. Set the admin secret

The `POST /admin/setup-clients` endpoint is protected by a secret you set here:

```sh
wrangler secret put ADMIN_SECRET
# enter a strong random value when prompted
```

---

### 5. Update the issuer URL

In `wrangler.jsonc`, set `ISSUER` to your Worker's public URL:

```jsonc
"vars": {
  "ISSUER": "https://worker-oauth.<your-subdomain>.workers.dev"
}
```

---

### 6. Run database migrations

Apply to the **remote** D1 database:

```sh
npm run db:migrate
```

To apply locally (for `wrangler dev`):

```sh
npm run db:migrate:local
```

---

### 7. Deploy

```sh
npm run deploy
```

---

### 8. Seed demo OAuth clients (optional)

After deploying, seed two demo clients (a public PKCE client and a confidential client):

```sh
curl -X POST https://worker-oauth.<your-subdomain>.workers.dev/admin/setup-clients \
  -H "X-Admin-Secret: <your-ADMIN_SECRET>"
```

---

## Local development

```sh
npm run db:migrate:local   # only needed once
npm run dev                # starts wrangler dev on http://localhost:8787
```

---

## Routes

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/login` | User login |
| `GET/POST` | `/register` | User registration |
| `GET` | `/dashboard` | Authenticated user dashboard |
| `GET/POST` | `/oauth/authorize` | Authorization / consent UI |
| `POST` | `/oauth/token` | Token endpoint |
| `GET` | `/oauth/userinfo` | OIDC UserInfo (Bearer token required) |
| `GET` | `/oauth/register` | Dynamic client registration (RFC 7591) |
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 discovery |
| `POST` | `/admin/setup-clients` | One-time demo client seeding (`X-Admin-Secret` header) |

## Supported scopes

`openid` · `profile` · `email` · `roles`
