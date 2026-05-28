// ---------------------------------------------------------------------------
// Cloudflare Worker bindings
// ---------------------------------------------------------------------------

export interface Env {
  /** D1 database – users, clients, tokens, sessions */
  DB: D1Database;
  /** KV namespace – HTTP sessions and JWT key pair */
  SESSIONS: KVNamespace;
  /** Workers Assets binding – serves public/ directory */
  ASSETS: Fetcher;

  // ---- Public variables (wrangler.jsonc > vars) ----
  /** Canonical issuer URL, e.g. https://auth.example.com */
  ISSUER: string;
  /** Access token lifetime in seconds (default: 3600) */
  TOKEN_EXPIRY?: string;
  /** Refresh token lifetime in seconds (default: 2592000) */
  REFRESH_TOKEN_EXPIRY?: string;

  // ---- Secrets (set via `wrangler secret put`) ----
  /** base64-encoded JSON Web Key – RSA private key for RS256 signing */
  JWT_PRIVATE_KEY?: string;
  /** base64-encoded JSON Web Key – RSA public key */
  JWT_PUBLIC_KEY?: string;
  /** Key ID matching the JWK */
  JWT_KID?: string;
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export interface User {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  created_at: number;
  updated_at: number;
}

export interface Role {
  id: string;
  name: string;
  description: string | null;
  created_at: number;
}

export interface Client {
  id: string;
  client_id: string;
  client_secret: string | null;
  name: string;
  redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  token_endpoint_auth_method: string;
  require_pkce: boolean;
}

export interface AuthorizationCode {
  code: string;
  client_id: string;
  user_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
  used: boolean;
}

export interface AccessTokenRecord {
  jti: string;
  client_id: string;
  user_id: string | null;
  scope: string;
  expires_at: number;
  revoked: boolean;
}

export interface RefreshTokenRecord {
  token: string;
  access_token_jti: string;
  client_id: string;
  user_id: string;
  scope: string;
  expires_at: number;
  revoked: boolean;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export interface PendingAuthorize {
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  responseType: string;
}

export interface SessionData {
  userId: string;
  username: string;
  pendingAuthorize?: PendingAuthorize;
}
