import type { Env, PendingAuthorize } from '../types';
import { getClientByClientId, createAuthorizationCode, getUserRoles } from '../db/queries';
import { generateToken } from '../utils/crypto';
import { getSession } from './session';

// ---------------------------------------------------------------------------
// GET /oauth/authorize
// ---------------------------------------------------------------------------
// Validates the authorization request, stores pending auth details in KV,
// then either shows the consent UI (user already logged in) or redirects
// to /login with a return URL.
// ---------------------------------------------------------------------------

export async function handleAuthorizeGet(
  request: Request,
  env: Env,
  url: URL,
): Promise<Response> {
  const p = url.searchParams;
  const responseType = p.get('response_type') ?? '';
  const clientId = p.get('client_id') ?? '';
  const redirectUri = p.get('redirect_uri') ?? '';
  const scope = p.get('scope') ?? 'openid';
  const state = p.get('state') ?? '';
  const codeChallenge = p.get('code_challenge') ?? '';
  const codeChallengeMethod = p.get('code_challenge_method') ?? 'S256';

  // --- Validate required parameters ---
  if (responseType !== 'code') {
    return oauthError('unsupported_response_type', 'Only response_type=code is supported');
  }
  if (!clientId) return oauthError('invalid_request', 'Missing client_id');
  if (!redirectUri) return oauthError('invalid_request', 'Missing redirect_uri');

  const client = await getClientByClientId(env.DB, clientId);
  if (!client) return oauthError('invalid_client', 'Unknown client_id');

  if (!client.redirect_uris.includes(redirectUri)) {
    return oauthError('invalid_request', 'redirect_uri not registered for this client');
  }

  // OAuth 2.1 – PKCE is mandatory for all clients
  if (!codeChallenge) {
    return redirectWithError(redirectUri, state, 'invalid_request', 'code_challenge is required');
  }
  if (!['S256', 'plain'].includes(codeChallengeMethod)) {
    return redirectWithError(
      redirectUri,
      state,
      'invalid_request',
      'Unsupported code_challenge_method',
    );
  }

  // --- Check session ---
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  const pending: PendingAuthorize = {
    clientId,
    redirectUri,
    scope,
    state,
    codeChallenge,
    codeChallengeMethod,
    responseType,
  };

  if (!session) {
    // Not logged in – store pending auth in KV and redirect to login
    const requestId = crypto.randomUUID();
    await env.SESSIONS.put(`auth_request:${requestId}`, JSON.stringify(pending), {
      expirationTtl: 600,
    });
    const loginUrl = new URL('/login', url);
    loginUrl.searchParams.set('auth_request', requestId);
    return Response.redirect(loginUrl.toString(), 302);
  }

  // --- Logged in – show consent page ---
  const roles = await getUserRoles(env.DB, session.userId);
  const requestId = crypto.randomUUID();
  await env.SESSIONS.put(`auth_request:${requestId}`, JSON.stringify(pending), {
    expirationTtl: 600,
  });

  const scopeList = scope
    .split(' ')
    .map(s => `<li class="flex items-center gap-2"><span class="text-green-500">✓</span>${s}</li>`)
    .join('');

  const html = await loadTemplate(env, '/authorize.html');
  const rendered = html
    .replace('{{CLIENT_NAME}}', escapeHtml(client.name))
    .replace('{{CLIENT_ID}}', escapeHtml(client.client_id))
    .replace('{{USERNAME}}', escapeHtml(session.username))
    .replace('{{ROLES}}', roles.map(r => escapeHtml(r)).join(', '))
    .replace('{{SCOPE_ITEMS}}', scopeList)
    .replace('{{REQUEST_ID}}', requestId);

  return new Response(rendered, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// ---------------------------------------------------------------------------
// POST /oauth/authorize  (user clicks Approve or Deny)
// ---------------------------------------------------------------------------

export async function handleAuthorizePost(
  request: Request,
  env: Env,
  _url: URL,
): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    return new Response('Unauthorized', { status: 401 });
  }

  const form = await request.formData();
  const action = form.get('action'); // "approve" | "deny"
  const requestId = form.get('request_id') as string | null;

  if (!requestId) return new Response('Bad Request', { status: 400 });

  const pending = await env.SESSIONS.get<PendingAuthorize>(
    `auth_request:${requestId}`,
    'json',
  );
  await env.SESSIONS.delete(`auth_request:${requestId}`);

  if (!pending) return new Response('Authorization request expired or not found', { status: 400 });

  if (action === 'deny') {
    return redirectWithError(pending.redirectUri, pending.state, 'access_denied', 'User denied access');
  }

  if (action !== 'approve') {
    return new Response('Bad Request', { status: 400 });
  }

  // Issue authorization code
  const code = generateToken(32);
  const now = Math.floor(Date.now() / 1000);

  await createAuthorizationCode(env.DB, {
    code,
    client_id: pending.clientId,
    user_id: session.userId,
    redirect_uri: pending.redirectUri,
    scope: pending.scope,
    code_challenge: pending.codeChallenge,
    code_challenge_method: pending.codeChallengeMethod,
    expires_at: now + 600, // 10 minutes
    used: false,
  });

  const redirectUrl = new URL(pending.redirectUri);
  redirectUrl.searchParams.set('code', code);
  if (pending.state) redirectUrl.searchParams.set('state', pending.state);

  return Response.redirect(redirectUrl.toString(), 302);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getSessionId(request: Request): string | null {
  const cookie = request.headers.get('Cookie') ?? '';
  const match = /(?:^|;\s*)session=([^;]+)/.exec(cookie);
  return match ? match[1] : null;
}

async function loadTemplate(env: Env, path: string): Promise<string> {
  const response = await env.ASSETS.fetch(new Request(`https://assets.internal${path}`));
  if (!response.ok) throw new Error(`Asset not found: ${path}`);
  return response.text();
}

function oauthError(error: string, description: string): Response {
  return new Response(
    JSON.stringify({ error, error_description: description }),
    { status: 400, headers: { 'Content-Type': 'application/json' } },
  );
}

function redirectWithError(
  redirectUri: string,
  state: string,
  error: string,
  description: string,
): Response {
  const url = new URL(redirectUri);
  url.searchParams.set('error', error);
  url.searchParams.set('error_description', description);
  if (state) url.searchParams.set('state', state);
  return Response.redirect(url.toString(), 302);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
