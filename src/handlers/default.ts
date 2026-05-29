import type { AuthRequest } from '@cloudflare/workers-oauth-provider';
import type { Env } from '../types';
import {
  getUserByUsername,
  getUserByEmail,
  getUserById,
  createUser,
  getUserRoles,
} from '../db/queries';
import { hashPassword, verifyPassword } from '../utils/crypto';
import {
  getSessionId,
  getSession,
  createSession,
  deleteSession,
  buildSetCookieHeader,
  buildClearCookieHeader,
} from './session';
import { loadTemplate, htmlResponse, escapeHtml } from './ui';

// ---------------------------------------------------------------------------
// Scope descriptions shown on the consent page
// ---------------------------------------------------------------------------

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'Read your username',
  email: 'Read your email address',
  roles: 'Read your account roles',
};

// ---------------------------------------------------------------------------
// Default handler – handles all non-API, non-token-endpoint routes
// ---------------------------------------------------------------------------

export const defaultHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname: path } = url;
    const method = request.method.toUpperCase();

    try {
      // CORS pre-flight for any remaining cross-origin requests
      if (method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type',
            'Access-Control-Max-Age': '86400',
          },
        });
      }

      // Redirect root → dashboard
      if (path === '/') {
        return Response.redirect(new URL('/dashboard', url).toString(), 302);
      }

      // ------------------------------------------------------------------
      // OAuth authorization UI
      // ------------------------------------------------------------------
      if (path === '/oauth/authorize') {
        if (method === 'GET') return handleAuthorizeGet(request, env, url);
        if (method === 'POST') return handleAuthorizePost(request, env, url);
      }

      // ------------------------------------------------------------------
      // UI routes
      // ------------------------------------------------------------------
      if (path === '/login') return handleLogin(request, env, url);
      if (path === '/register') return handleRegister(request, env, url);

      if (path === '/dashboard' && method === 'GET') {
        return handleDashboard(request, env, url);
      }
      if (path === '/logout' && method === 'GET') {
        return handleLogout(request, env);
      }

      // ------------------------------------------------------------------
      // Session-authenticated API routes (used by the dashboard)
      // ------------------------------------------------------------------
      if (path === '/api/me' && method === 'GET') {
        return handleApiMe(request, env);
      }

      // ------------------------------------------------------------------
      // Admin: one-time client seeding for demo clients
      // ------------------------------------------------------------------
      if (path === '/admin/setup-clients' && method === 'POST') {
        return handleSetupClients(request, env);
      }

      // Fall through to static assets
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error('defaultHandler error:', err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

// ---------------------------------------------------------------------------
// GET /oauth/authorize – show consent UI (or redirect to login if no session)
// ---------------------------------------------------------------------------

async function handleAuthorizeGet(request: Request, env: Env, url: URL): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    // Store the full authorize URL so we can resume after login
    const returnId = crypto.randomUUID();
    await env.SESSIONS.put(`auth_request:${returnId}`, request.url, {
      expirationTtl: 600, // 10 minutes
    });
    const loginUrl = new URL('/login', url);
    loginUrl.searchParams.set('auth_request', returnId);
    return Response.redirect(loginUrl.toString(), 302);
  }

  // Parse the OAuth authorization request via the library
  let oauthReqInfo: AuthRequest;
  try {
    oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch {
    return htmlResponse(
      '<h1>Invalid authorization request</h1><p>Missing or invalid OAuth parameters.</p>',
      400,
    );
  }

  // Look up the client
  const client = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);
  if (!client) {
    return htmlResponse(
      `<h1>Unknown client</h1><p>Client <code>${escapeHtml(oauthReqInfo.clientId)}</code> is not registered. Register it first via <code>POST /oauth/register</code> or <code>POST /admin/setup-clients</code>.</p>`,
      400,
    );
  }

  // Store the parsed request so POST /oauth/authorize can retrieve it
  const requestId = crypto.randomUUID();
  await env.SESSIONS.put(`consent_req:${requestId}`, JSON.stringify(oauthReqInfo), {
    expirationTtl: 600,
  });

  // Fetch roles for display
  const roles = await getUserRoles(env.DB, session.userId);

  // Build scope list HTML
  const scopeItems = oauthReqInfo.scope
    .map((s) => {
      const desc = SCOPE_DESCRIPTIONS[s] ?? s;
      return `<li class="flex items-center gap-2"><span class="inline-block w-2 h-2 rounded-full bg-indigo-400 flex-shrink-0"></span>${escapeHtml(desc)}</li>`;
    })
    .join('\n          ');

  const html = await loadTemplate(env, '/authorize.html');
  const rendered = html
    .replace('{{USERNAME}}', escapeHtml(session.username))
    .replace('{{CLIENT_NAME}}', escapeHtml(client.clientName ?? oauthReqInfo.clientId))
    .replace('{{CLIENT_ID}}', escapeHtml(oauthReqInfo.clientId))
    .replace('{{SCOPE_ITEMS}}', scopeItems)
    .replace('{{ROLES}}', escapeHtml(roles.join(', ') || 'No roles'))
    .replace('{{REQUEST_ID}}', requestId);

  return htmlResponse(rendered);
}

// ---------------------------------------------------------------------------
// POST /oauth/authorize – approve or deny the authorization request
// ---------------------------------------------------------------------------

async function handleAuthorizePost(request: Request, env: Env, url: URL): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    return Response.redirect(new URL('/login', url).toString(), 302);
  }

  const form = await request.formData();
  const requestId = (form.get('request_id') as string | null) ?? '';
  const action = (form.get('action') as string | null) ?? '';

  // Retrieve the stored OAuth request info
  const stored = await env.SESSIONS.get(`consent_req:${requestId}`);
  if (!stored) {
    return htmlResponse('<h1>Session expired</h1><p>Please restart the authorization flow.</p>', 400);
  }

  const oauthReqInfo: AuthRequest = JSON.parse(stored);
  // Clean up from KV
  await env.SESSIONS.delete(`consent_req:${requestId}`);

  if (action === 'deny') {
    const denyUrl = new URL(oauthReqInfo.redirectUri);
    denyUrl.searchParams.set('error', 'access_denied');
    denyUrl.searchParams.set('error_description', 'User denied the authorization request');
    if (oauthReqInfo.state) denyUrl.searchParams.set('state', oauthReqInfo.state);
    return Response.redirect(denyUrl.toString(), 302);
  }

  if (action !== 'approve') {
    return htmlResponse('<h1>Invalid action</h1>', 400);
  }

  // Fetch user details to store in grant props (encrypted by the library)
  const user = await getUserById(env.DB, session.userId);
  const roles = await getUserRoles(env.DB, session.userId);

  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: session.userId,
    metadata: { username: session.username },
    scope: oauthReqInfo.scope,
    props: {
      userId: session.userId,
      username: session.username,
      email: user?.email ?? '',
      roles,
    },
  });

  return Response.redirect(redirectTo, 302);
}

// ---------------------------------------------------------------------------
// GET /login  – render login page
// POST /login – authenticate and create session
// ---------------------------------------------------------------------------

async function handleLogin(request: Request, env: Env, url: URL): Promise<Response> {
  const authRequestId = url.searchParams.get('auth_request');

  if (request.method === 'GET') {
    const html = await loadTemplate(env, '/login.html');
    return htmlResponse(
      html.replace('{{ERROR}}', '').replace('{{AUTH_REQUEST_ID}}', authRequestId ?? ''),
    );
  }

  // POST
  const form = await request.formData();
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const authReqId = (form.get('auth_request_id') as string | null) ?? '';

  const renderError = async (msg: string): Promise<Response> => {
    const html = await loadTemplate(env, '/login.html');
    return htmlResponse(
      html.replace('{{ERROR}}', escapeHtml(msg)).replace('{{AUTH_REQUEST_ID}}', authReqId),
      401,
    );
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
  const headers = new Headers({ 'Set-Cookie': buildSetCookieHeader(sessionId, isSecure) });

  // Resume a pending OAuth flow if present
  if (authReqId) {
    const returnUrl = await env.SESSIONS.get(`auth_request:${authReqId}`);
    if (returnUrl) {
      await env.SESSIONS.delete(`auth_request:${authReqId}`);
      headers.set('Location', returnUrl);
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

async function handleRegister(request: Request, env: Env, url: URL): Promise<Response> {
  if (request.method === 'GET') {
    const html = await loadTemplate(env, '/register.html');
    return htmlResponse(html.replace('{{ERROR}}', ''));
  }

  const form = await request.formData();
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const email = (form.get('email') as string | null)?.trim().toLowerCase() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const confirmPassword = (form.get('confirm_password') as string | null) ?? '';

  const renderError = async (msg: string): Promise<Response> => {
    const html = await loadTemplate(env, '/register.html');
    return htmlResponse(html.replace('{{ERROR}}', escapeHtml(msg)), 400);
  };

  if (!username || !email || !password) return renderError('All fields are required.');
  if (password !== confirmPassword) return renderError('Passwords do not match.');
  if (password.length < 8) return renderError('Password must be at least 8 characters.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return renderError('Invalid email address.');

  if (await getUserByUsername(env.DB, username)) return renderError('Username already taken.');
  if (await getUserByEmail(env.DB, email)) return renderError('Email already registered.');

  const id = crypto.randomUUID();
  await createUser(env.DB, {
    id,
    username,
    email,
    password_hash: await hashPassword(password),
  });

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

async function handleDashboard(request: Request, env: Env, url: URL): Promise<Response> {
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

async function handleLogout(request: Request, env: Env): Promise<Response> {
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
// GET /api/me – session-authenticated; used by the dashboard JS
// ---------------------------------------------------------------------------

async function handleApiMe(request: Request, env: Env): Promise<Response> {
  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const user = await getUserById(env.DB, session.userId);
  if (!user) {
    return Response.json({ error: 'User not found' }, { status: 404 });
  }

  const roles = await getUserRoles(env.DB, user.id);

  return Response.json({
    id: user.id,
    username: user.username,
    email: user.email,
    roles,
    created_at: user.created_at,
  });
}

// ---------------------------------------------------------------------------
// POST /admin/setup-clients – one-time seeding of demo OAuth clients
//   Requires header: X-Admin-Secret matching env.ADMIN_SECRET (wrangler secret)
// ---------------------------------------------------------------------------

async function handleSetupClients(request: Request, env: Env): Promise<Response> {
  const adminSecret = (env as unknown as { ADMIN_SECRET?: string }).ADMIN_SECRET;
  const provided = request.headers.get('X-Admin-Secret');

  if (!adminSecret || provided !== adminSecret) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const results: Array<{ clientId: string; clientSecret?: string; status: string }> = [];

  // Demo public client (SPA / CLI – no secret, PKCE required)
  try {
    const existing = await env.OAUTH_PROVIDER.lookupClient('demo-public');
    if (existing) {
      results.push({ clientId: 'demo-public', status: 'already exists' });
    } else {
      const c = await env.OAUTH_PROVIDER.createClient({
        clientId: 'demo-public',
        clientName: 'Demo Public Client',
        redirectUris: ['http://localhost:3000/callback', 'https://oauthdebugger.com/debug'],
        grantTypes: ['authorization_code', 'refresh_token'],
        tokenEndpointAuthMethod: 'none',
      });
      results.push({ clientId: c.clientId, status: 'created' });
    }
  } catch (err) {
    results.push({ clientId: 'demo-public', status: `error: ${String(err)}` });
  }

  // Demo confidential client (server-side app – has client secret)
  try {
    const existing = await env.OAUTH_PROVIDER.lookupClient('demo-confidential');
    if (existing) {
      results.push({ clientId: 'demo-confidential', status: 'already exists' });
    } else {
      const c = await env.OAUTH_PROVIDER.createClient({
        clientId: 'demo-confidential',
        clientSecret: 'super-secret-value',
        clientName: 'Demo Confidential Client',
        redirectUris: ['http://localhost:3000/callback', 'https://oauthdebugger.com/debug'],
        grantTypes: ['authorization_code', 'refresh_token'],
        tokenEndpointAuthMethod: 'client_secret_basic',
      });
      results.push({ clientId: c.clientId, clientSecret: c.clientSecret, status: 'created' });
    }
  } catch (err) {
    results.push({ clientId: 'demo-confidential', status: `error: ${String(err)}` });
  }

  return Response.json({ results });
}
