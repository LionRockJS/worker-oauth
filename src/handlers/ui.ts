import type { Env } from '../types';
import {
  getUserByUsername,
  getUserByEmail,
  getUserById,
  createUser,
  getUserRoles,
} from '../db/queries';
import { hashPassword, verifyPassword } from '../utils/crypto';
import { getKeys, signJWT } from '../utils/jwt';
import {
  getSessionId,
  getSession,
  createSession,
  deleteSession,
  buildSetCookieHeader,
  buildClearCookieHeader,
} from './session';
import type { PendingAuthorize } from '../types';

// ---------------------------------------------------------------------------
// GET /login  – render login page
// POST /login – authenticate and create session
// ---------------------------------------------------------------------------

export async function handleLogin(request: Request, env: Env, url: URL): Promise<Response> {
  const authRequestId = url.searchParams.get('auth_request');

  if (request.method === 'GET') {
    const html = await loadTemplate(env, '/login.html');
    const rendered = html
      .replace('{{ERROR}}', '')
      .replace('{{AUTH_REQUEST_ID}}', authRequestId ?? '');
    return htmlResponse(rendered);
  }

  // POST
  const form = await request.formData();
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const authReqId = (form.get('auth_request_id') as string | null) ?? '';

  const renderError = async (msg: string) => {
    const html = await loadTemplate(env, '/login.html');
    const rendered = html
      .replace('{{ERROR}}', escapeHtml(msg))
      .replace('{{AUTH_REQUEST_ID}}', authReqId);
    return htmlResponse(rendered, 401);
  };

  if (!username || !password) return renderError('Username and password are required.');

  const user = await getUserByUsername(env.DB, username);
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return renderError('Invalid username or password.');
  }

  const sessionId = await createSession(env.SESSIONS, {
    userId: user.id,
    username: user.username,
  });

  const isSecure = url.protocol === 'https:';
  const headers = new Headers({
    'Set-Cookie': buildSetCookieHeader(sessionId, isSecure),
  });

  // Resume a pending OAuth flow if present
  if (authReqId) {
    const pending = await env.SESSIONS.get<PendingAuthorize>(
      `auth_request:${authReqId}`,
      'json',
    );
    if (pending) {
      // Re-direct to /oauth/authorize so the consent page renders
      const authorizeUrl = new URL('/oauth/authorize', url);
      authorizeUrl.searchParams.set('response_type', pending.responseType);
      authorizeUrl.searchParams.set('client_id', pending.clientId);
      authorizeUrl.searchParams.set('redirect_uri', pending.redirectUri);
      authorizeUrl.searchParams.set('scope', pending.scope);
      authorizeUrl.searchParams.set('state', pending.state);
      authorizeUrl.searchParams.set('code_challenge', pending.codeChallenge);
      authorizeUrl.searchParams.set('code_challenge_method', pending.codeChallengeMethod);
      headers.set('Location', authorizeUrl.toString());
      return new Response(null, { status: 302, headers });
    }
  }

  headers.set('Location', '/dashboard');
  return new Response(null, { status: 302, headers });
}

// ---------------------------------------------------------------------------
// GET /register  – render registration page
// POST /register – create account
// ---------------------------------------------------------------------------

export async function handleRegister(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method === 'GET') {
    const html = await loadTemplate(env, '/register.html');
    return htmlResponse(html.replace('{{ERROR}}', ''));
  }

  const form = await request.formData();
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const email = (form.get('email') as string | null)?.trim().toLowerCase() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const confirmPassword = (form.get('confirm_password') as string | null) ?? '';

  const renderError = async (msg: string) => {
    const html = await loadTemplate(env, '/register.html');
    return htmlResponse(html.replace('{{ERROR}}', escapeHtml(msg)), 400);
  };

  if (!username || !email || !password) return renderError('All fields are required.');
  if (password !== confirmPassword) return renderError('Passwords do not match.');
  if (password.length < 8) return renderError('Password must be at least 8 characters.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return renderError('Invalid email address.');

  const existingUser = await getUserByUsername(env.DB, username);
  if (existingUser) return renderError('Username already taken.');

  const existingEmail = await getUserByEmail(env.DB, email);
  if (existingEmail) return renderError('Email already registered.');

  const id = crypto.randomUUID();
  const passwordHash = await hashPassword(password);

  await createUser(env.DB, { id, username, email, password_hash: passwordHash });

  const sessionId = await createSession(env.SESSIONS, { userId: id, username });
  const isSecure = url.protocol === 'https:';

  return new Response(null, {
    status: 302,
    headers: {
      'Set-Cookie': buildSetCookieHeader(sessionId, isSecure),
      Location: '/dashboard',
    },
  });
}

// ---------------------------------------------------------------------------
// GET /dashboard – serve the dashboard HTML (JS fetches /api/me)
// ---------------------------------------------------------------------------

export async function handleDashboard(request: Request, env: Env, url: URL): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    return Response.redirect(new URL('/login', url).toString(), 302);
  }

  const html = await loadTemplate(env, '/dashboard.html');
  return htmlResponse(html);
}

// ---------------------------------------------------------------------------
// GET /logout
// ---------------------------------------------------------------------------

export async function handleLogout(request: Request, env: Env, _url: URL): Promise<Response> {
  const sessionId = getSessionId(request);
  if (sessionId) await deleteSession(env.SESSIONS, sessionId);

  return new Response(null, {
    status: 302,
    headers: {
      'Set-Cookie': buildClearCookieHeader(),
      Location: '/login',
    },
  });
}

// ---------------------------------------------------------------------------
// GET /api/me  – return current user info as JSON (consumed by dashboard JS)
// ---------------------------------------------------------------------------

export async function handleApiMe(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const user = await getUserById(env.DB, session.userId);
  if (!user) {
    return new Response(JSON.stringify({ error: 'User not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const roles = await getUserRoles(env.DB, user.id);

  return new Response(
    JSON.stringify({
      id: user.id,
      username: user.username,
      email: user.email,
      roles,
      created_at: user.created_at,
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
}

// ---------------------------------------------------------------------------
// POST /api/token  – generate a sample access token for the logged-in user
//                   (useful for testing downstream resource servers)
// ---------------------------------------------------------------------------

export async function handleApiToken(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const roles = await getUserRoles(env.DB, session.userId);
  const now = Math.floor(Date.now() / 1000);
  const tokenExpiry = parseInt(env.TOKEN_EXPIRY ?? '3600', 10);

  const keys = await getKeys(env);
  const accessToken = await signJWT(
    {
      iss: env.ISSUER,
      sub: session.userId,
      aud: 'self',
      exp: now + tokenExpiry,
      iat: now,
      jti: crypto.randomUUID(),
      roles,
      scope: 'openid profile email roles',
      client_id: 'dashboard',
    },
    keys.privateKey,
    keys.kid,
  );

  return new Response(
    JSON.stringify({ access_token: accessToken, token_type: 'Bearer', expires_in: tokenExpiry }),
    { headers: { 'Content-Type': 'application/json' } },
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loadTemplate(env: Env, path: string): Promise<string> {
  const response = await env.ASSETS.fetch(new Request(`https://assets.internal${path}`));
  if (!response.ok) throw new Error(`Asset not found: ${path}`);
  return response.text();
}

function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
