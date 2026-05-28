import type { Env } from '../types';
import {
  getClientByClientId,
  getAndConsumeAuthorizationCode,
  createAccessToken,
  createRefreshToken,
  getAccessToken,
  revokeAccessToken,
  revokeRefreshTokenByJti,
  getAndConsumeRefreshToken,
  getUserById,
  getUserRoles,
} from '../db/queries';
import { verifyPKCE, generateToken } from '../utils/crypto';
import { getKeys, signJWT, verifyJWT } from '../utils/jwt';

// ---------------------------------------------------------------------------
// POST /oauth/token
// ---------------------------------------------------------------------------

export async function handleToken(request: Request, env: Env): Promise<Response> {
  const contentType = request.headers.get('Content-Type') ?? '';
  if (!contentType.includes('application/x-www-form-urlencoded')) {
    return tokenError('invalid_request', 'Content-Type must be application/x-www-form-urlencoded');
  }

  const body = await request.formData();
  const grantType = body.get('grant_type') as string | null;

  if (grantType === 'authorization_code') {
    return handleAuthorizationCode(request, env, body);
  }
  if (grantType === 'refresh_token') {
    return handleRefreshToken(request, env, body);
  }

  return tokenError('unsupported_grant_type', `Unsupported grant_type: ${grantType ?? ''}`);
}

// ---------------------------------------------------------------------------
// authorization_code grant
// ---------------------------------------------------------------------------

async function handleAuthorizationCode(
  request: Request,
  env: Env,
  body: FormData,
): Promise<Response> {
  const code = body.get('code') as string | null;
  const redirectUri = body.get('redirect_uri') as string | null;
  const codeVerifier = body.get('code_verifier') as string | null;
  const clientId = body.get('client_id') as string | null;

  if (!code) return tokenError('invalid_request', 'Missing code');
  if (!redirectUri) return tokenError('invalid_request', 'Missing redirect_uri');
  if (!codeVerifier) return tokenError('invalid_request', 'Missing code_verifier (PKCE required)');

  // Authenticate client
  const { client, error: authError } = await authenticateClient(request, env, clientId);
  if (authError || !client) return tokenError('invalid_client', authError ?? 'Client authentication failed');

  // Retrieve and consume the authorization code
  const authCode = await getAndConsumeAuthorizationCode(env.DB, code);
  if (!authCode) return tokenError('invalid_grant', 'Authorization code not found or already used');

  const now = Math.floor(Date.now() / 1000);
  if (authCode.expires_at < now) {
    return tokenError('invalid_grant', 'Authorization code has expired');
  }
  if (authCode.client_id !== client.client_id) {
    return tokenError('invalid_grant', 'Code was not issued to this client');
  }
  if (authCode.redirect_uri !== redirectUri) {
    return tokenError('invalid_grant', 'redirect_uri mismatch');
  }

  // Verify PKCE
  const pkceOk = await verifyPKCE(codeVerifier, authCode.code_challenge, authCode.code_challenge_method);
  if (!pkceOk) return tokenError('invalid_grant', 'PKCE verification failed');

  return issueTokens(env, client.client_id, authCode.user_id, authCode.scope);
}

// ---------------------------------------------------------------------------
// refresh_token grant (with rotation)
// ---------------------------------------------------------------------------

async function handleRefreshToken(
  request: Request,
  env: Env,
  body: FormData,
): Promise<Response> {
  const refreshTokenValue = body.get('refresh_token') as string | null;
  const clientId = body.get('client_id') as string | null;

  if (!refreshTokenValue) return tokenError('invalid_request', 'Missing refresh_token');

  const { client, error: authError } = await authenticateClient(request, env, clientId);
  if (authError || !client) return tokenError('invalid_client', authError ?? 'Client authentication failed');

  const rt = await getAndConsumeRefreshToken(env.DB, refreshTokenValue);
  if (!rt) return tokenError('invalid_grant', 'Refresh token not found, expired, or already used');

  const now = Math.floor(Date.now() / 1000);
  if (rt.expires_at < now) return tokenError('invalid_grant', 'Refresh token has expired');
  if (rt.client_id !== client.client_id) {
    return tokenError('invalid_grant', 'Refresh token was not issued to this client');
  }

  // Revoke old access token
  await revokeAccessToken(env.DB, rt.access_token_jti);

  return issueTokens(env, client.client_id, rt.user_id, rt.scope);
}

// ---------------------------------------------------------------------------
// POST /oauth/revoke  (RFC 7009)
// ---------------------------------------------------------------------------

export async function handleRevoke(request: Request, env: Env): Promise<Response> {
  const body = await request.formData();
  const token = body.get('token') as string | null;
  const tokenTypeHint = body.get('token_type_hint') as string | null;
  const clientId = body.get('client_id') as string | null;

  if (!token) return new Response(null, { status: 200 }); // RFC 7009 §2.2: always 200

  const { client, error } = await authenticateClient(request, env, clientId);
  if (error || !client) return new Response(null, { status: 200 });

  // Try as access token (JWT – extract jti)
  if (!tokenTypeHint || tokenTypeHint === 'access_token') {
    try {
      const keys = await getKeys(env);
      const payload = await verifyJWT(token, keys.publicKey);
      if (payload.jti) {
        await revokeAccessToken(env.DB, payload.jti);
        await revokeRefreshTokenByJti(env.DB, payload.jti);
      }
      return new Response(null, { status: 200 });
    } catch {
      // Not a valid access token – try as refresh token below
    }
  }

  // Try as refresh token (opaque)
  const rt = await getAndConsumeRefreshToken(env.DB, token);
  if (rt) {
    await revokeAccessToken(env.DB, rt.access_token_jti);
  }

  return new Response(null, { status: 200 });
}

// ---------------------------------------------------------------------------
// POST /oauth/introspect  (RFC 7662)
// ---------------------------------------------------------------------------

export async function handleIntrospect(request: Request, env: Env): Promise<Response> {
  const body = await request.formData();
  const token = body.get('token') as string | null;
  const clientId = body.get('client_id') as string | null;

  const { client, error } = await authenticateClient(request, env, clientId);
  if (error || !client) return jsonResponse({ active: false });

  if (!token) return jsonResponse({ active: false });

  try {
    const keys = await getKeys(env);
    const payload = await verifyJWT(token, keys.publicKey);

    if (!payload.jti) return jsonResponse({ active: false });

    const record = await getAccessToken(env.DB, payload.jti);
    if (!record || record.revoked) return jsonResponse({ active: false });

    const now = Math.floor(Date.now() / 1000);
    if (record.expires_at < now) return jsonResponse({ active: false });

    return jsonResponse({
      active: true,
      scope: payload.scope,
      client_id: payload.client_id,
      username: payload.sub,
      token_type: 'Bearer',
      exp: payload.exp,
      iat: payload.iat,
      sub: payload.sub,
      iss: payload.iss,
      jti: payload.jti,
      roles: payload.roles ?? [],
    });
  } catch {
    return jsonResponse({ active: false });
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Issue a new access + refresh token pair. */
async function issueTokens(
  env: Env,
  clientId: string,
  userId: string,
  scope: string,
): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const tokenExpiry = parseInt(env.TOKEN_EXPIRY ?? '3600', 10);
  const refreshExpiry = parseInt(env.REFRESH_TOKEN_EXPIRY ?? '2592000', 10);

  // Fetch user & roles to embed in the JWT
  const user = await getUserById(env.DB, userId);
  const roles = user ? await getUserRoles(env.DB, userId) : [];

  const keys = await getKeys(env);
  const jti = crypto.randomUUID();

  const accessTokenJwt = await signJWT(
    {
      iss: env.ISSUER,
      sub: userId,
      aud: clientId,
      exp: now + tokenExpiry,
      iat: now,
      jti,
      roles,
      scope,
      client_id: clientId,
    },
    keys.privateKey,
    keys.kid,
  );

  // Persist access token record for revocation tracking
  await createAccessToken(env.DB, {
    jti,
    client_id: clientId,
    user_id: userId,
    scope,
    expires_at: now + tokenExpiry,
    revoked: false,
  });

  // Issue refresh token
  const refreshTokenValue = generateToken(40);
  await createRefreshToken(env.DB, {
    token: refreshTokenValue,
    access_token_jti: jti,
    client_id: clientId,
    user_id: userId,
    scope,
    expires_at: now + refreshExpiry,
    revoked: false,
  });

  return jsonResponse({
    access_token: accessTokenJwt,
    token_type: 'Bearer',
    expires_in: tokenExpiry,
    refresh_token: refreshTokenValue,
    scope,
  });
}

/** Authenticate the client from Basic auth header or body parameters. */
async function authenticateClient(
  request: Request,
  env: Env,
  bodyClientId: string | null,
): Promise<{ client: Awaited<ReturnType<typeof getClientByClientId>>; error: null } | { client: null; error: string }> {
  let clientId: string | null = null;
  let clientSecret: string | null = null;

  // Try HTTP Basic authentication
  const authHeader = request.headers.get('Authorization') ?? '';
  if (authHeader.startsWith('Basic ')) {
    const decoded = atob(authHeader.slice(6));
    const colonIdx = decoded.indexOf(':');
    if (colonIdx !== -1) {
      clientId = decoded.slice(0, colonIdx);
      clientSecret = decoded.slice(colonIdx + 1);
    }
  }

  // Fall back to body parameters
  if (!clientId) clientId = bodyClientId;

  if (!clientId) return { client: null, error: 'Missing client_id' };

  const client = await getClientByClientId(env.DB, clientId);
  if (!client) return { client: null, error: 'Unknown client_id' };

  // Public clients have no secret (PKCE is their authentication mechanism)
  if (client.token_endpoint_auth_method === 'none') {
    return { client, error: null };
  }

  // Confidential clients must provide the secret
  if (!client.client_secret) {
    return { client: null, error: 'Client has no secret configured' };
  }
  if (!clientSecret || clientSecret !== client.client_secret) {
    return { client: null, error: 'Invalid client_secret' };
  }

  return { client, error: null };
}

function tokenError(error: string, description: string): Response {
  return new Response(JSON.stringify({ error, error_description: description }), {
    status: 400,
    headers: { 'Content-Type': 'application/json' },
  });
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
}
