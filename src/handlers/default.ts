import type { AuthRequest } from '@cloudflare/workers-oauth-provider';
import type { Env, SessionData } from '../types';
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
import { rejectCrossOriginMutation, timingSafeEqualStrings } from '../utils/security';

// ---------------------------------------------------------------------------
// Scope descriptions shown on the consent page
// ---------------------------------------------------------------------------

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'Read your username',
  email: 'Read your email address',
  roles: 'Read your account roles',
};

const LOGIN_RATE_LIMIT_TTL = 15 * 60;
const MAX_FAILED_LOGINS = 8;
const RECAPTCHA_ACTION = 'submit';
const DEFAULT_RECAPTCHA_MIN_SCORE = 0.5;
const CONSENT_APPROVAL_PREFIX = 'consent_approval:';

type RecaptchaVerification =
  | { ok: true }
  | { ok: false; message: string; countFailedLogin?: boolean };

interface RecaptchaAssessmentResponse {
  tokenProperties?: {
    valid?: boolean;
    action?: string;
    hostname?: string;
    invalidReason?: string;
  };
  riskAnalysis?: {
    score?: number | string;
    reasons?: string[];
  };
}

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

      const crossOriginMutation = rejectCrossOriginMutation(request);
      if (crossOriginMutation) return crossOriginMutation;

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

      // Fall through to static assets (only known public paths)
      const staticAssetPaths = ['/', '/authorize.html', '/dashboard.html', '/login.html', '/register.html'];
      const isStaticAsset = staticAssetPaths.includes(path) || path.startsWith('/favicon') || path.startsWith('/_');
      if (!isStaticAsset) {
        return new Response('Not Found', { status: 404 });
      }
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
      `<h1>Unknown client</h1><p>Client <code>${escapeHtml(oauthReqInfo.clientId)}</code> is not registered.</p>`,
      400,
    );
  }

  if (await hasApprovedConsent(env.SESSIONS, session.userId, oauthReqInfo.clientId, oauthReqInfo.scope)) {
    return completeUserAuthorization(env, session, oauthReqInfo);
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
    .replace('{{REQUEST_ID}}', requestId)
    .replace('{{AUTHORIZE_ACTION}}', new URL('/oauth/authorize', env.ISSUER).toString());

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

  if (action !== 'approve' && action !== 'deny') {
    return htmlResponse('<h1>Invalid action</h1>', 400);
  }

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

  await rememberApprovedConsent(env.SESSIONS, session.userId, oauthReqInfo.clientId, oauthReqInfo.scope);
  return completeUserAuthorization(env, session, oauthReqInfo);
}

async function completeUserAuthorization(
  env: Env,
  session: SessionData,
  oauthReqInfo: AuthRequest,
): Promise<Response> {
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

async function hasApprovedConsent(
  kv: KVNamespace,
  userId: string,
  clientId: string,
  requestedScopes: string[],
): Promise<boolean> {
  const approved = await readApprovedScopes(kv, userId, clientId);
  if (!approved) return false;

  return normalizeScopes(requestedScopes).every((scope) => approved.has(scope));
}

async function rememberApprovedConsent(
  kv: KVNamespace,
  userId: string,
  clientId: string,
  approvedScopes: string[],
): Promise<void> {
  const existing = await readApprovedScopes(kv, userId, clientId);
  const scopes = normalizeScopes([...(existing ?? []), ...approvedScopes]);
  await kv.put(getConsentApprovalKey(userId, clientId), JSON.stringify(scopes));
}

async function readApprovedScopes(
  kv: KVNamespace,
  userId: string,
  clientId: string,
): Promise<Set<string> | null> {
  const raw = await kv.get(getConsentApprovalKey(userId, clientId));
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return null;
    return new Set(parsed.filter((scope): scope is string => typeof scope === 'string'));
  } catch {
    return null;
  }
}

function normalizeScopes(scopes: string[]): string[] {
  return Array.from(new Set(scopes)).sort();
}

function getConsentApprovalKey(userId: string, clientId: string): string {
  return `${CONSENT_APPROVAL_PREFIX}${encodeURIComponent(userId)}:${encodeURIComponent(clientId)}`;
}

// ---------------------------------------------------------------------------
// GET /login  – render login page
// POST /login – authenticate and create session
// ---------------------------------------------------------------------------

async function handleLogin(request: Request, env: Env, url: URL): Promise<Response> {
  const authRequestId = url.searchParams.get('auth_request');

  if (request.method === 'GET') {
    return renderLoginPage(env, '', authRequestId ?? '');
  }

  // POST
  const form = await request.formData();
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const authReqId = (form.get('auth_request_id') as string | null) ?? '';
  const recaptchaToken =
    getFormString(form, 'recaptcha_token') || getFormString(form, 'g-recaptcha-response');

  const renderError = async (msg: string): Promise<Response> => {
    return renderLoginPage(env, msg, authReqId, 401);
  };

  if (!username || !password) return renderError('Username and password are required.');

  const rateLimitKey = await getLoginRateLimitKey(request, username);
  const failedAttempts = await getFailedLoginCount(env.SESSIONS, rateLimitKey);
  if (failedAttempts >= MAX_FAILED_LOGINS) {
    return renderError('Too many failed attempts. Please try again later.');
  }

  const recaptcha = await verifyRecaptcha(request, env, recaptchaToken, RECAPTCHA_ACTION);
  if (!recaptcha.ok) {
    if (recaptcha.countFailedLogin) await recordFailedLogin(env.SESSIONS, rateLimitKey, failedAttempts);
    return renderError(recaptcha.message);
  }

  const user = await getUserByUsername(env.DB, username);
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    await recordFailedLogin(env.SESSIONS, rateLimitKey, failedAttempts);
    return renderError('Invalid username or password.');
  }
  await clearFailedLogins(env.SESSIONS, rateLimitKey);

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

async function renderLoginPage(
  env: Env,
  error: string,
  authRequestId: string,
  status = 200,
): Promise<Response> {
  const html = await loadTemplate(env, '/login.html');
  const siteKey = escapeHtml(env.RECAPTCHA_SITE_KEY ?? '');
  return htmlResponse(
    html
      .replaceAll('{{RECAPTCHA_SITE_KEY}}', siteKey)
      .replace('{{ERROR}}', escapeHtml(error))
      .replace('{{AUTH_REQUEST_ID}}', escapeHtml(authRequestId)),
    status,
  );
}

async function verifyRecaptcha(
  request: Request,
  env: Env,
  token: string,
  expectedAction: string,
): Promise<RecaptchaVerification> {
  if (!token) {
    return {
      ok: false,
      message: 'Please complete the reCAPTCHA verification.',
      countFailedLogin: true,
    };
  }

  const siteKey = env.RECAPTCHA_SITE_KEY?.trim();
  const projectId = env.RECAPTCHA_PROJECT_ID?.trim();
  const apiKey = env.RECAPTCHA_API_KEY?.trim();
  if (!siteKey || !projectId || !apiKey) {
    // reCAPTCHA is partially configured – allow login but log a warning.
    // Set RECAPTCHA_PROJECT_ID in wrangler.jsonc to enable full verification.
    console.warn('reCAPTCHA verification skipped: RECAPTCHA_PROJECT_ID or RECAPTCHA_API_KEY not configured.');
    return { ok: true };
  }

  const endpoint = new URL(
    `https://recaptchaenterprise.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/assessments`,
  );
  endpoint.searchParams.set('key', apiKey);

  let assessment: RecaptchaAssessmentResponse;
  try {
    const response = await fetch(endpoint.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        event: {
          token,
          siteKey,
          expectedAction,
          userAgent: request.headers.get('User-Agent') ?? undefined,
          userIpAddress: request.headers.get('CF-Connecting-IP') ?? undefined,
        },
      }),
    });

    if (!response.ok) {
      console.error('reCAPTCHA assessment failed:', response.status);
      return { ok: false, message: 'Could not verify reCAPTCHA. Please try again.' };
    }

    assessment = (await response.json()) as RecaptchaAssessmentResponse;
  } catch (err) {
    console.error('reCAPTCHA assessment error:', err);
    return { ok: false, message: 'Could not verify reCAPTCHA. Please try again.' };
  }

  const tokenProperties = assessment.tokenProperties;
  if (!tokenProperties?.valid) {
    console.warn('reCAPTCHA token invalid:', tokenProperties?.invalidReason ?? 'unknown');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
      countFailedLogin: true,
    };
  }

  if (tokenProperties.action !== expectedAction) {
    console.warn('reCAPTCHA action mismatch:', tokenProperties.action ?? 'missing');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
      countFailedLogin: true,
    };
  }

  const requestHostname = new URL(request.url).hostname.toLowerCase();
  const recaptchaHostname = tokenProperties.hostname?.toLowerCase();
  if (!recaptchaHostname || recaptchaHostname !== requestHostname) {
    console.warn('reCAPTCHA hostname mismatch:', recaptchaHostname ?? 'missing');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
      countFailedLogin: true,
    };
  }

  const score = parseRecaptchaScore(assessment.riskAnalysis?.score);
  if (score === null || score < getRecaptchaMinScore(env)) {
    console.warn('reCAPTCHA score below threshold:', score ?? 'missing');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
      countFailedLogin: true,
    };
  }

  return { ok: true };
}

function parseRecaptchaScore(score: number | string | undefined): number | null {
  const parsed = typeof score === 'string' ? Number(score) : score;
  return typeof parsed === 'number' && Number.isFinite(parsed) ? parsed : null;
}

function getRecaptchaMinScore(env: Env): number {
  const configured = env.RECAPTCHA_MIN_SCORE ? Number(env.RECAPTCHA_MIN_SCORE) : DEFAULT_RECAPTCHA_MIN_SCORE;
  if (!Number.isFinite(configured) || configured < 0 || configured > 1) {
    return DEFAULT_RECAPTCHA_MIN_SCORE;
  }
  return configured;
}

function getFormString(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === 'string' ? value : '';
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

  return Response.json(
    {
      id: user.id,
      username: user.username,
      email: user.email,
      roles,
      created_at: user.created_at,
    },
    { headers: { 'Cache-Control': 'no-store' } },
  );
}

// ---------------------------------------------------------------------------
// POST /admin/setup-clients – create/update OAuth clients
//   Requires header: X-Admin-Secret matching env.ADMIN_SECRET (wrangler secret)
//
//   Request body (application/json):
//   {
//     "clients": [
//       {
//         "clientId": "my-app",            // optional; provider assigns if omitted
//         "clientName": "My Application",  // required
//         "redirectUris": ["https://app.example.com/callback"],
//         "grantTypes": ["authorization_code", "refresh_token"],
//         "tokenEndpointAuthMethod": "client_secret_post",  // or "none" for public
//         "clientSecret": "..."            // omit for public (PKCE-only) clients
//       }
//     ]
//   }
//
//   Built-in demo clients are still controlled by ALLOW_DEMO_CLIENTS=true.
// ---------------------------------------------------------------------------

interface ClientDef {
  clientId?: string;
  clientName: string;
  redirectUris: string[];
  grantTypes?: string[];
  tokenEndpointAuthMethod?: string;
  clientSecret?: string;
}

async function handleSetupClients(request: Request, env: Env): Promise<Response> {
  const adminSecret = env.ADMIN_SECRET;
  const provided = request.headers.get('X-Admin-Secret');

  if (!adminSecret || !provided || !(await timingSafeEqualStrings(provided, adminSecret))) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  const results: Array<{ clientId: string; status: string }> = [];
  const allowDemoClients = env.ALLOW_DEMO_CLIENTS === 'true';

  // Demo public client (SPA / CLI – no secret, PKCE required)
  if (allowDemoClients) {
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
  } else {
    await deleteClientIfPresent(env, 'demo-public');
    results.push({ clientId: 'demo-public', status: 'deleted/skipped; set ALLOW_DEMO_CLIENTS=true to seed demo clients' });
  }

  // Demo confidential client (server-side app – has client secret)
  if (allowDemoClients) {
    try {
      const demoSecret = env.DEMO_CONFIDENTIAL_CLIENT_SECRET;
      if (!demoSecret) {
        results.push({ clientId: 'demo-confidential', status: 'error: DEMO_CONFIDENTIAL_CLIENT_SECRET secret not set' });
      } else {
        const existing = await env.OAUTH_PROVIDER.lookupClient('demo-confidential');
        if (existing) {
          await env.OAUTH_PROVIDER.updateClient(existing.clientId, { clientSecret: demoSecret });
          results.push({ clientId: 'demo-confidential', status: 'secret updated' });
        } else {
          const c = await env.OAUTH_PROVIDER.createClient({
            clientId: 'demo-confidential',
            clientSecret: demoSecret,
            clientName: 'Demo Confidential Client',
            redirectUris: ['http://localhost:3000/callback', 'https://oauthdebugger.com/debug'],
            grantTypes: ['authorization_code', 'refresh_token'],
            tokenEndpointAuthMethod: 'client_secret_basic',
          });
          results.push({ clientId: c.clientId, status: 'created' });
        }
      }
    } catch (err) {
      results.push({ clientId: 'demo-confidential', status: `error: ${String(err)}` });
    }
  } else {
    await deleteClientIfPresent(env, 'demo-confidential');
    results.push({ clientId: 'demo-confidential', status: 'deleted/skipped; set ALLOW_DEMO_CLIENTS=true to seed demo clients' });
  }

  // Arbitrary clients from request body
  let bodyClients: ClientDef[] = [];
  try {
    const ct = request.headers.get('Content-Type') ?? '';
    if (ct.includes('application/json')) {
      const body = await request.json<{ clients?: unknown }>();
      if (Array.isArray(body.clients)) {
        bodyClients = body.clients as ClientDef[];
      }
    }
  } catch {
    // No body or invalid JSON – proceed with demo clients only
  }

  for (const def of bodyClients) {
    if (!def.clientName || !Array.isArray(def.redirectUris) || def.redirectUris.length === 0) {
      results.push({ clientId: def.clientId ?? def.clientName ?? '(unknown)', status: 'error: clientName and redirectUris are required' });
      continue;
    }

    try {
      const existing = def.clientId
        ? await env.OAUTH_PROVIDER.lookupClient(def.clientId)
        : (await env.OAUTH_PROVIDER.listClients({ limit: 200 })).items.find((c) => c.clientName === def.clientName);

      const clientDef = {
        clientName: def.clientName,
        redirectUris: def.redirectUris,
        grantTypes: def.grantTypes ?? ['authorization_code', 'refresh_token'],
        tokenEndpointAuthMethod: def.tokenEndpointAuthMethod ?? (def.clientSecret ? 'client_secret_post' : 'none'),
        ...(def.clientSecret ? { clientSecret: def.clientSecret } : {}),
      };

      if (existing) {
        await env.OAUTH_PROVIDER.updateClient(existing.clientId, clientDef);
        results.push({ clientId: existing.clientId, status: 'updated' });
      } else {
        const created = await env.OAUTH_PROVIDER.createClient({
          ...(def.clientId ? { clientId: def.clientId } : {}),
          ...clientDef,
        });
        results.push({ clientId: created.clientId, status: 'created' });
      }
    } catch (err) {
      results.push({ clientId: def.clientId ?? def.clientName, status: `error: ${String(err)}` });
    }
  }

  return Response.json({ results });
}

async function getLoginRateLimitKey(request: Request, username: string): Promise<string> {
  const ip = request.headers.get('CF-Connecting-IP') ?? request.headers.get('X-Forwarded-For') ?? 'unknown';
  const material = `${ip}:${username.toLowerCase()}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(material));
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `login_fail:${hex}`;
}

async function getFailedLoginCount(kv: KVNamespace, key: string): Promise<number> {
  const value = await kv.get(key);
  return value ? parseInt(value, 10) || 0 : 0;
}

async function recordFailedLogin(kv: KVNamespace, key: string, previousCount: number): Promise<void> {
  await kv.put(key, String(previousCount + 1), { expirationTtl: LOGIN_RATE_LIMIT_TTL });
}

async function clearFailedLogins(kv: KVNamespace, key: string): Promise<void> {
  await kv.delete(key);
}

async function deleteClientIfPresent(env: Env, clientId: string): Promise<void> {
  const existing = await env.OAUTH_PROVIDER.lookupClient(clientId);
  if (existing) await env.OAUTH_PROVIDER.deleteClient(existing.clientId);
}
