import type { OAuthHelpers } from '@cloudflare/workers-oauth-provider';

// ---------------------------------------------------------------------------
// Cloudflare Worker bindings
// ---------------------------------------------------------------------------

export interface Env {
  /** D1 database – users, roles */
  DB: D1Database;
  /** KV namespace – user sessions (HttpOnly cookie) */
  SESSIONS: KVNamespace;
  /** KV namespace – OAuth token/grant storage (used by workers-oauth-provider) */
  OAUTH_KV: KVNamespace;
  /** Workers Assets binding – serves public/ directory */
  ASSETS: Fetcher;
  /** OAuth provider helpers – injected by OAuthProvider wrapper */
  OAUTH_PROVIDER: OAuthHelpers;

  // ---- Public variables (wrangler.jsonc > vars) ----
  /** Canonical issuer URL, e.g. https://auth.example.com */
  ISSUER: string;
  /** Public reCAPTCHA Enterprise site key used on the login page */
  RECAPTCHA_SITE_KEY: string;
  /** Google Cloud project ID that owns the reCAPTCHA Enterprise key */
  RECAPTCHA_PROJECT_ID?: string;
  /** Minimum accepted reCAPTCHA risk score, defaults to 0.5 */
  RECAPTCHA_MIN_SCORE?: string;

  // ---- Secrets / deploy-time flags ----
  /** Protects POST /admin/setup-clients */
  ADMIN_SECRET?: string;
  /** Google reCAPTCHA Enterprise assessment API key */
  RECAPTCHA_API_KEY?: string;
  /** Set to "true" only when demo OAuth clients should be seeded */
  ALLOW_DEMO_CLIENTS?: string;
  /** Required when ALLOW_DEMO_CLIENTS is true and demo-confidential is seeded */
  DEMO_CONFIDENTIAL_CLIENT_SECRET?: string;
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

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export interface SessionData {
  userId: string;
  username: string;
}

// ---------------------------------------------------------------------------
// Props stored in OAuth grants (encrypted by the library)
// ---------------------------------------------------------------------------

export interface UserProps {
  userId: string;
  username: string;
  email: string;
  roles: string[];
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
