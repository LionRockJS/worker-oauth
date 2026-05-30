-- =============================================================
-- Migration 0001 – Initial schema for the OAuth 2.1 provider
-- =============================================================

-- ------------------------------------------------------------
-- Users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id           TEXT    PRIMARY KEY,
  username     TEXT    NOT NULL UNIQUE,
  email        TEXT    NOT NULL UNIQUE,
  password_hash TEXT   NOT NULL,
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  updated_at   INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ------------------------------------------------------------
-- Roles
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
  id          TEXT    PRIMARY KEY,
  name        TEXT    NOT NULL UNIQUE,
  description TEXT,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ------------------------------------------------------------
-- User ↔ Role assignments
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_roles (
  user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id    TEXT    NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (user_id, role_id)
);

-- ------------------------------------------------------------
-- OAuth 2.1 clients
--   redirect_uris, grant_types and scopes are JSON arrays.
--   token_endpoint_auth_method: "client_secret_basic" |
--                                "client_secret_post"  |
--                                "none" (public client)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS clients (
  id                          TEXT    PRIMARY KEY,
  client_id                   TEXT    NOT NULL UNIQUE,
  client_secret               TEXT,                   -- NULL → public client
  name                        TEXT    NOT NULL,
  redirect_uris               TEXT    NOT NULL,       -- JSON array
  grant_types                 TEXT    NOT NULL DEFAULT '["authorization_code","refresh_token"]',
  scopes                      TEXT    NOT NULL DEFAULT '["openid","profile","email","roles"]',
  token_endpoint_auth_method  TEXT    NOT NULL DEFAULT 'client_secret_basic',
  require_pkce                INTEGER NOT NULL DEFAULT 1,  -- 1 = mandatory (OAuth 2.1)
  created_at                  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- ------------------------------------------------------------
-- Authorization codes  (single-use, 10-minute TTL)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS authorization_codes (
  code                   TEXT    PRIMARY KEY,
  client_id              TEXT    NOT NULL,
  user_id                TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri           TEXT    NOT NULL,
  scope                  TEXT    NOT NULL,
  code_challenge         TEXT    NOT NULL,
  code_challenge_method  TEXT    NOT NULL DEFAULT 'S256',
  expires_at             INTEGER NOT NULL,
  used                   INTEGER NOT NULL DEFAULT 0,
  created_at             INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires
  ON authorization_codes(expires_at);

-- ------------------------------------------------------------
-- Access tokens  (JWT jti tracked for revocation)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS access_tokens (
  jti        TEXT    PRIMARY KEY,
  client_id  TEXT    NOT NULL,
  user_id    TEXT    REFERENCES users(id) ON DELETE SET NULL,
  scope      TEXT    NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_expires
  ON access_tokens(expires_at);

-- ------------------------------------------------------------
-- Refresh tokens  (opaque, rotate on use)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token             TEXT    PRIMARY KEY,
  access_token_jti  TEXT    NOT NULL,
  client_id         TEXT    NOT NULL,
  user_id           TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope             TEXT    NOT NULL,
  expires_at        INTEGER NOT NULL,
  revoked           INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires
  ON refresh_tokens(expires_at);

-- ============================================================
-- Seed data
-- ============================================================

-- Default roles
INSERT OR IGNORE INTO roles (id, name, description) VALUES
  ('role_admin', 'admin', 'Full administrative access'),
  ('role_user',  'user',  'Standard authenticated user');
