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

### 4. Set required secrets

The `POST /admin/setup-clients` endpoint is protected by a secret you set here:

```sh
wrangler secret put ADMIN_SECRET
# enter a strong random value when prompted
```

---

### 5. Update public configuration

In `wrangler.jsonc`, set `ISSUER` to your Worker's public URL and configure
the reCAPTCHA Enterprise site key used by `/login`:

```jsonc
"vars": {
  "ISSUER": "https://id.eventuai.com",
  "RECAPTCHA_SITE_KEY": "6LfhfwQtAAAAACRmsenmnvRlj6eNikByvdpDi_8J",
  "RECAPTCHA_PROJECT_ID": "<google-cloud-project-id>",
  "RECAPTCHA_MIN_SCORE": "0.5"
}
```

The site key and project ID are not secrets. Store the Google Cloud API key
used to create reCAPTCHA assessments as a Worker secret:

```sh
wrangler secret put RECAPTCHA_API_KEY
```

`POST /login` fails closed if `RECAPTCHA_PROJECT_ID` or
`RECAPTCHA_API_KEY` is missing.

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

### 8. Register OAuth clients

`POST /admin/setup-clients` creates or updates any number of clients in one
call. Pass a JSON body with a `clients` array; the request must include the
`X-Admin-Secret` header.

**Register a confidential client** (e.g. the CMS Worker):

```sh
curl -X POST https://id.eventuai.com/admin/setup-clients \
  -H "X-Admin-Secret: <your-ADMIN_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{
    "clients": [
      {
        "clientName": "Worker CMS",
        "redirectUris": ["https://cms.example.com/auth/callback"],
        "tokenEndpointAuthMethod": "client_secret_post",
        "clientSecret": "<strong-random-secret>"
      }
    ]
  }'
```

The response includes the assigned `clientId`; copy it into the CMS
`EVENTUAI_CLIENT_ID` var and store the matching secret with
`wrangler secret put EVENTUAI_CLIENT_SECRET`.

**Register a public (PKCE-only) client** (e.g. an SPA or CLI tool):

```sh
curl -X POST https://id.eventuai.com/admin/setup-clients \
  -H "X-Admin-Secret: <your-ADMIN_SECRET>" \
  -H "Content-Type: application/json" \
  -d '{
    "clients": [
      {
        "clientId": "my-spa",
        "clientName": "My SPA",
        "redirectUris": ["https://app.example.com/callback"],
        "tokenEndpointAuthMethod": "none"
      }
    ]
  }'
```

**Register multiple clients at once** by adding more objects to the array.

Each client object supports:

| Field | Required | Description |
|-------|----------|-------------|
| `clientName` | Yes | Human-readable name (also used to find existing clients when `clientId` is omitted) |
| `redirectUris` | Yes | Allowed redirect URIs |
| `clientId` | No | Fixed client ID; provider assigns one if omitted |
| `clientSecret` | No | Omit for public / PKCE-only clients |
| `grantTypes` | No | Defaults to `["authorization_code", "refresh_token"]` |
| `tokenEndpointAuthMethod` | No | `"client_secret_post"` (default when secret provided), `"client_secret_basic"`, or `"none"` |

Demo clients (`demo-public`, `demo-confidential`) are controlled separately by
setting `ALLOW_DEMO_CLIENTS=true`; set `DEMO_CONFIDENTIAL_CLIENT_SECRET` before
seeding `demo-confidential`.

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
| `GET` | `/.well-known/oauth-authorization-server` | RFC 8414 discovery |
| `POST` | `/admin/setup-clients` | Create/update OAuth clients (`X-Admin-Secret` header) |

## Supported scopes

`openid` · `profile` · `email` · `roles`
