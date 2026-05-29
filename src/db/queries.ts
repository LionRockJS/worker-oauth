import type {
  User,
  Client,
  AuthorizationCode,
  AccessTokenRecord,
  RefreshTokenRecord,
} from '../types';

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export async function getUserByUsername(db: D1Database, username: string): Promise<User | null> {
  return db
    .prepare('SELECT * FROM users WHERE username = ?')
    .bind(username)
    .first<User>();
}

export async function getUserByEmail(db: D1Database, email: string): Promise<User | null> {
  return db
    .prepare('SELECT * FROM users WHERE email = ?')
    .bind(email)
    .first<User>();
}

export async function getUserById(db: D1Database, id: string): Promise<User | null> {
  return db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first<User>();
}

export async function createUser(
  db: D1Database,
  user: Pick<User, 'id' | 'username' | 'email' | 'password_hash'>,
): Promise<void> {
  await db
    .prepare('INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)')
    .bind(user.id, user.username, user.email, user.password_hash)
    .run();

  // Assign the default "user" role
  const roleRow = await db
    .prepare("SELECT id FROM roles WHERE name = 'user'")
    .first<{ id: string }>();

  if (roleRow) {
    await db
      .prepare('INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)')
      .bind(user.id, roleRow.id)
      .run();
  }
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

export async function getUserRoles(db: D1Database, userId: string): Promise<string[]> {
  const result = await db
    .prepare(
      `SELECT r.name
       FROM roles r
       JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = ?`,
    )
    .bind(userId)
    .all<{ name: string }>();

  return result.results.map(r => r.name);
}

// ---------------------------------------------------------------------------
// Clients
// ---------------------------------------------------------------------------

export async function getClientByClientId(db: D1Database, clientId: string): Promise<Client | null> {
  type Row = Omit<Client, 'redirect_uris' | 'grant_types' | 'scopes' | 'require_pkce'> & {
    redirect_uris: string;
    grant_types: string;
    scopes: string;
    require_pkce: number;
  };

  const row = await db
    .prepare('SELECT * FROM clients WHERE client_id = ?')
    .bind(clientId)
    .first<Row>();

  if (!row) return null;

  return {
    ...row,
    redirect_uris: JSON.parse(row.redirect_uris) as string[],
    grant_types: JSON.parse(row.grant_types) as string[],
    scopes: JSON.parse(row.scopes) as string[],
    require_pkce: row.require_pkce !== 0,
  };
}

// ---------------------------------------------------------------------------
// Authorization codes
// ---------------------------------------------------------------------------

export async function createAuthorizationCode(
  db: D1Database,
  code: AuthorizationCode,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO authorization_codes
         (code, client_id, user_id, redirect_uri, scope,
          code_challenge, code_challenge_method, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      code.code,
      code.client_id,
      code.user_id,
      code.redirect_uri,
      code.scope,
      code.code_challenge,
      code.code_challenge_method,
      code.expires_at,
    )
    .run();
}

export async function getAndConsumeAuthorizationCode(
  db: D1Database,
  code: string,
): Promise<AuthorizationCode | null> {
  type Row = Omit<AuthorizationCode, 'used'> & { used: number };

  const row = await db
    .prepare('SELECT * FROM authorization_codes WHERE code = ? AND used = 0')
    .bind(code)
    .first<Row>();

  if (!row) return null;

  // Mark as used immediately (single-use guarantee)
  await db
    .prepare('UPDATE authorization_codes SET used = 1 WHERE code = ?')
    .bind(code)
    .run();

  return { ...row, used: false };
}

// ---------------------------------------------------------------------------
// Access tokens
// ---------------------------------------------------------------------------

export async function createAccessToken(db: D1Database, token: AccessTokenRecord): Promise<void> {
  await db
    .prepare(
      `INSERT INTO access_tokens (jti, client_id, user_id, scope, expires_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(token.jti, token.client_id, token.user_id, token.scope, token.expires_at)
    .run();
}

export async function getAccessToken(
  db: D1Database,
  jti: string,
): Promise<AccessTokenRecord | null> {
  type Row = Omit<AccessTokenRecord, 'revoked'> & { revoked: number };

  const row = await db
    .prepare('SELECT * FROM access_tokens WHERE jti = ?')
    .bind(jti)
    .first<Row>();

  if (!row) return null;
  return { ...row, revoked: row.revoked !== 0 };
}

export async function revokeAccessToken(db: D1Database, jti: string): Promise<void> {
  await db
    .prepare('UPDATE access_tokens SET revoked = 1 WHERE jti = ?')
    .bind(jti)
    .run();
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

export async function createRefreshToken(
  db: D1Database,
  token: RefreshTokenRecord,
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO refresh_tokens
         (token, access_token_jti, client_id, user_id, scope, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      token.token,
      token.access_token_jti,
      token.client_id,
      token.user_id,
      token.scope,
      token.expires_at,
    )
    .run();
}

export async function getAndConsumeRefreshToken(
  db: D1Database,
  token: string,
): Promise<RefreshTokenRecord | null> {
  type Row = Omit<RefreshTokenRecord, 'revoked'> & { revoked: number };

  const row = await db
    .prepare('SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0')
    .bind(token)
    .first<Row>();

  if (!row) return null;

  // Rotate: invalidate the old refresh token immediately
  await db
    .prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token = ?')
    .bind(token)
    .run();

  return { ...row, revoked: false };
}

export async function revokeRefreshTokenByJti(
  db: D1Database,
  accessTokenJti: string,
): Promise<void> {
  await db
    .prepare('UPDATE refresh_tokens SET revoked = 1 WHERE access_token_jti = ?')
    .bind(accessTokenJti)
    .run();
}
