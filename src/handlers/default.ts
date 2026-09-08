import type { AuthRequest } from '@cloudflare/workers-oauth-provider';
import type { Env, SessionData } from '../types';
import {
  getUserByUsername,
  getUserByEmail,
  getUserById,
  createUser,
  getUserRoles,
} from '../db/queries';
import { hashPassword, verifyPassword, getDecoyHash } from '../utils/crypto';
import {
  getSessionId,
  getSession,
  createSession,
  deleteSession,
  buildSetCookieHeader,
  buildClearCookieHeader,
} from './session';
import { loadTemplate, htmlResponse, escapeHtml } from './ui';
import {
  rejectCrossOriginMutation,
  timingSafeEqualStrings,
  ensureCsrfToken,
  validateCsrf,
  isLocalHost,
  readForm,
  RequestInputError,
} from '../utils/security';

import { validAuthorization, hasDuplicateOAuthParameters } from '../utils/oauth';

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
// Fixed-window attempt budgets; all attempts reserve capacity before verification.
const MAX_LOGIN_ATTEMPTS = 8;
const MAX_ATTEMPTS_PER_USERNAME = 15;
const MAX_ATTEMPTS_PER_IP = 30;
const RECAPTCHA_ACTION = 'submit';
const DEFAULT_RECAPTCHA_MIN_SCORE = 0.5;
const CONSENT_APPROVAL_PREFIX = 'consent_approval:';
const CONSENT_APPROVAL_TTL = 90 * 24 * 60 * 60; // 90 days
// Argon2id hashes 19 MiB per call; cap input length to prevent a memory/CPU DoS.
const MAX_PASSWORD_LENGTH = 128;

type RecaptchaVerification =
  | { ok: true }
  | { ok: false; message: string };

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
      // CORS pre-flight. These routes are cookie-authenticated and first-party,
      // so only the canonical issuer origin is allowed credentialed access —
      // never a wildcard.
      if (method === 'OPTIONS') {
        const headers = new Headers({
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Authorization, Content-Type',
          'Access-Control-Max-Age': '86400',
          Vary: 'Origin',
        });
        const origin = request.headers.get('Origin');
        let issuerOrigin = '';
        try {
          issuerOrigin = new URL(env.ISSUER).origin;
        } catch {
          issuerOrigin = '';
        }
        if (origin && origin === issuerOrigin) {
          headers.set('Access-Control-Allow-Origin', origin);
          headers.set('Access-Control-Allow-Credentials', 'true');
        }
        return new Response(null, { status: 204, headers });
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
        if (method === 'GET') return await handleAuthorizeGet(request, env, url);
        if (method === 'POST') return await handleAuthorizePost(request, env, url);
      }

      // ------------------------------------------------------------------
      // UI routes
      // ------------------------------------------------------------------
      if (path === '/login' && (method === 'GET' || method === 'POST')) return await handleLogin(request, env, url);
      if (path === '/register' && (method === 'GET' || method === 'POST')) return await handleRegister(request, env, url);

      if (path === '/dashboard' && method === 'GET') {
        return await handleDashboard(request, env, url);
      }
      if (path === '/logout' && method === 'POST') {
        return await handleLogout(request, env);
      }

      // ------------------------------------------------------------------
      // Session-authenticated API routes (used by the dashboard)
      // ------------------------------------------------------------------
      if (path === '/api/me' && method === 'GET') {
        return await handleApiMe(request, env);
      }

      // ------------------------------------------------------------------
      // Admin: one-time client seeding for demo clients
      // ------------------------------------------------------------------
      if (path === '/admin/setup-clients' && method === 'POST') {
        return await handleSetupClients(request, env);
      }

      const routeMethods: Record<string, string> = {
        '/login': 'GET, POST', '/register': 'GET, POST', '/oauth/authorize': 'GET, POST',
        '/logout': 'POST', '/dashboard': 'GET', '/api/me': 'GET', '/admin/setup-clients': 'POST',
      };
      if (routeMethods[path]) return new Response('Method Not Allowed', {
        status: 405, headers: { Allow: routeMethods[path] },
      });
      // Serve only real public assets; templates must pass through their handlers.
      const assets = ['/styles.css', '/js/login.js', '/js/register.js', '/js/authorize.js', '/js/dashboard.js', '/favicon.ico'];
      if ((method === 'GET' || method === 'HEAD') && assets.includes(path)) return await env.ASSETS.fetch(request);
      return new Response('Not Found', { status: 404 });
    } catch (err) {
      if (err instanceof RequestInputError) return new Response(err.message, { status: err.status });
      console.error(JSON.stringify({ event: 'handler_failed' }));
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

// ---------------------------------------------------------------------------
// GET /oauth/authorize – show consent UI (or redirect to login if no session)
// ---------------------------------------------------------------------------

async function handleAuthorizeGet(request: Request, env: Env, url: URL): Promise<Response> {
  // Parse the OAuth authorization request via the library
  let oauthReqInfo: AuthRequest;
  try {
    if (hasDuplicateOAuthParameters(url)) throw new Error('Duplicate parameter');
    oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch {
    return htmlResponse(
      '<h1>Invalid authorization request</h1><p>Missing or invalid OAuth parameters.</p>',
      400,
    );
  }

  // Look up the client
  const client = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);
  if (!validAuthorization(oauthReqInfo, client)) {
    return htmlResponse(
      '<h1>Invalid authorization request</h1><p>Check the client, redirect URI, scopes, and S256 PKCE parameters.</p>',
      400,
    );
  }

  const sessionId = getSessionId(request);
  const session = sessionId ? await getSession(env.SESSIONS, sessionId) : null;

  if (!session) {
    // Bind the continuation to this browser’s CSRF cookie, with explicit expiry.
    const returnId = crypto.randomUUID();
    const csrf = ensureCsrfToken(request, url.protocol === 'https:');
    await env.SESSIONS.put(`auth_request:${returnId}`, JSON.stringify({ url: request.url, csrfToken: csrf.token, expiresAt: Date.now() + 600_000 }), {
      expirationTtl: 600, // 10 minutes
    });
    const loginUrl = new URL('/login', url);
    loginUrl.searchParams.set('auth_request', returnId);
    const response = new Response(null, { status: 302, headers: { Location: loginUrl.toString() } });
    if (csrf.setCookie) response.headers.append('Set-Cookie', csrf.setCookie);
    return response;
  }

  if (await hasApprovedConsent(env.SESSIONS, session.userId, oauthReqInfo.clientId, oauthReqInfo.scope)) {
    return completeUserAuthorization(env, session, oauthReqInfo);
  }

  // Store the parsed request so POST /oauth/authorize can retrieve it. Bind it
  // to the exact session so another login by the same user cannot consume it.
  const requestId = crypto.randomUUID();
  await env.SESSIONS.put(
    `consent_req:${requestId}`,
    JSON.stringify({ req: oauthReqInfo, sessionId, expiresAt: Date.now() + 600_000 }),
    { expirationTtl: 600 },
  );

  // Fetch roles for display
  const roles = await getUserRoles(env.DB, session.userId);

  const secure = url.protocol === 'https:';
  const csrf = ensureCsrfToken(request, secure);

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
    .replace('{{CLIENT_NAME}}', escapeHtml(client?.clientName ?? oauthReqInfo.clientId))
    .replace('{{CLIENT_ID}}', escapeHtml(oauthReqInfo.clientId))
    .replace('{{SCOPE_ITEMS}}', scopeItems)
    .replace('{{ROLES}}', escapeHtml(roles.join(', ') || 'No roles'))
    .replace('{{REQUEST_ID}}', requestId)
    .replace('{{CSRF_TOKEN}}', escapeHtml(csrf.token))
    .replace('{{AUTHORIZE_ACTION}}', new URL('/oauth/authorize', env.ISSUER).toString());

  const response = htmlResponse(rendered);
  if (csrf.setCookie) response.headers.append('Set-Cookie', csrf.setCookie);
  return response;
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

  const form = await readForm(request);

  if (!(await validateCsrf(request, form))) {
    return htmlResponse('<h1>Invalid request</h1><p>CSRF validation failed. Please restart the authorization flow.</p>', 403);
  }

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

  const { req: oauthReqInfo, sessionId: boundSessionId, expiresAt } = JSON.parse(stored) as {
    req: AuthRequest;
    sessionId: string;
    expiresAt: number;
  };

  // The consent request must belong to the session submitting it.
  if (boundSessionId !== sessionId || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    return htmlResponse('<h1>Invalid request</h1><p>This authorization request does not belong to your session.</p>', 403);
  }

  const client = await env.OAUTH_PROVIDER.lookupClient(oauthReqInfo.clientId);
  if (!validAuthorization(oauthReqInfo, client)) return htmlResponse('<h1>Invalid authorization request</h1>', 400);
  // KV deletion is eventually consistent. A DO reservation makes consent single-use.
  if (!(await rlStub(env, `consent:${requestId}`).consume(600, 1))) {
    return htmlResponse('<h1>Authorization request already used</h1>', 400);
  }
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
  if (!user) return htmlResponse('<h1>Session expired</h1>', 401);
  const roles = oauthReqInfo.scope.includes('roles') ? await getUserRoles(env.DB, session.userId) : [];

  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReqInfo,
    userId: session.userId,
    metadata: { username: session.username },
    scope: oauthReqInfo.scope,
    props: {
      userId: session.userId,
      username: oauthReqInfo.scope.includes('profile') ? user.username : '',
      email: oauthReqInfo.scope.includes('email') ? user.email : '',
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
  await kv.put(getConsentApprovalKey(userId, clientId), JSON.stringify(scopes), {
    expirationTtl: CONSENT_APPROVAL_TTL,
  });
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
    return renderLoginPage(request, env, '', authRequestId ?? '');
  }

  // POST
  const form = await readForm(request);
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const authReqId = (form.get('auth_request_id') as string | null) ?? '';
  const recaptchaToken =
    getFormString(form, 'recaptcha_token') || getFormString(form, 'g-recaptcha-response');

  const renderError = async (msg: string): Promise<Response> => {
    return renderLoginPage(request, env, msg, authReqId, 401);
  };

  if (!(await validateCsrf(request, form))) {
    return renderError('Your session expired. Please try again.');
  }

  if (username.length > 64) return renderError('Invalid username or password.');
  if (!username || !password) return renderError('Username and password are required.');

  const limit = await loginRateLimitNames(request, username);

  // Reserve each attempt atomically before reCAPTCHA or Argon2, including successes.
  const allowed = await Promise.all([
    rlStub(env, limit.ipUser).consume(LOGIN_RATE_LIMIT_TTL, MAX_LOGIN_ATTEMPTS),
    rlStub(env, limit.ip).consume(LOGIN_RATE_LIMIT_TTL, MAX_ATTEMPTS_PER_IP),
    rlStub(env, limit.user).consume(LOGIN_RATE_LIMIT_TTL, MAX_ATTEMPTS_PER_USERNAME),
  ]);
  if (allowed.includes(false)) {
    return new Response('Too many attempts. Please try again later.', {
      status: 429, headers: { 'Retry-After': String(LOGIN_RATE_LIMIT_TTL) },
    });
  }

  const recaptcha = await verifyRecaptcha(request, env, recaptchaToken, RECAPTCHA_ACTION);
  if (!recaptcha.ok) {
    return renderError(recaptcha.message);
  }

  // Over-length passwords are rejected before hashing (Argon2id DoS guard) but
  // still counted as a failed attempt and given the generic error.
  const user = password.length > MAX_PASSWORD_LENGTH ? null : await getUserByUsername(env.DB, username);

  // Always run a verify (against a decoy hash for unknown users) so response
  // timing does not reveal whether the username exists.
  let passwordOk = false;
  if (user) {
    passwordOk = await verifyPassword(password, user.password_hash);
  } else {
    await verifyPassword(password.slice(0, MAX_PASSWORD_LENGTH), await getDecoyHash());
  }

  if (!user || !passwordOk) {
    return renderError('Invalid username or password.');
  }

  const previousSession = getSessionId(request);
  if (previousSession) await deleteSession(env.SESSIONS, previousSession);

  const sessionId = await createSession(env.SESSIONS, {
    userId: user.id,
    username: user.username,
  });

  const isSecure = url.protocol === 'https:';
  const headers = new Headers({ 'Set-Cookie': buildSetCookieHeader(sessionId, isSecure) });

  // Resume a pending OAuth flow if present
  if (authReqId) {
    const continuation = await env.SESSIONS.get<{ url: string; csrfToken: string; expiresAt: number }>(`auth_request:${authReqId}`, 'json');
    if (continuation && Number.isFinite(continuation.expiresAt) && continuation.expiresAt > Date.now() &&
        typeof continuation.csrfToken === 'string' && await timingSafeEqualStrings(continuation.csrfToken, getFormString(form, 'csrf_token'))) {
      await env.SESSIONS.delete(`auth_request:${authReqId}`);
      const resume = new URL(continuation.url);
      if (resume.origin !== url.origin || resume.pathname !== '/oauth/authorize') {
        throw new RequestInputError(400, 'Invalid authorization continuation');
      }
      headers.set('Location', resume.toString());
      return new Response(null, { status: 302, headers });
    }
  }

  headers.set('Location', '/dashboard');
  return new Response(null, { status: 302, headers });
}

async function renderLoginPage(
  request: Request,
  env: Env,
  error: string,
  authRequestId: string,
  status = 200,
): Promise<Response> {
  const html = await loadTemplate(env, '/login.html');
  const siteKey = escapeHtml(env.RECAPTCHA_SITE_KEY ?? '');
  const secure = new URL(request.url).protocol === 'https:';
  const csrf = ensureCsrfToken(request, secure);
  const response = htmlResponse(
    html
      .replaceAll('{{RECAPTCHA_SITE_KEY}}', siteKey)
      .replace('{{ERROR}}', escapeHtml(error))
      .replace('{{CSRF_TOKEN}}', escapeHtml(csrf.token))
      .replace('{{AUTH_REQUEST_ID}}', escapeHtml(authRequestId)),
    status,
  );
  if (csrf.setCookie) response.headers.append('Set-Cookie', csrf.setCookie);
  return response;
}

async function verifyRecaptcha(
  request: Request,
  env: Env,
  token: string,
  expectedAction: string,
): Promise<RecaptchaVerification> {
  if (isLocalHost(new URL(request.url).hostname) && env.RECAPTCHA_ENFORCE === 'false') return { ok: true };
  if (!token) {
    return {
      ok: false,
      message: 'Please complete the reCAPTCHA verification.',
    };
  }

  const siteKey = env.RECAPTCHA_SITE_KEY?.trim();
  const projectId = env.RECAPTCHA_PROJECT_ID?.trim();
  const apiKey = env.RECAPTCHA_API_KEY?.trim();
  if (!siteKey || !projectId || !apiKey) {
    console.error('reCAPTCHA misconfigured (RECAPTCHA_PROJECT_ID or RECAPTCHA_API_KEY missing) – failing closed.');
    return { ok: false, message: 'Login is temporarily unavailable. Please try again later.' };
  }

  const endpoint = new URL(
    `https://recaptchaenterprise.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/assessments`,
  );
  endpoint.searchParams.set('key', apiKey);

  let assessment: RecaptchaAssessmentResponse;
  try {
    const response = await fetch(endpoint.toString(), {
      method: 'POST',
      signal: AbortSignal.timeout(5000),
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
  } catch {
    console.error('reCAPTCHA assessment unavailable');
    return { ok: false, message: 'Could not verify reCAPTCHA. Please try again.' };
  }

  const tokenProperties = assessment.tokenProperties;
  if (!tokenProperties?.valid) {
    console.warn('reCAPTCHA token invalid:', tokenProperties?.invalidReason ?? 'unknown');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
    };
  }

  if (tokenProperties.action !== expectedAction) {
    console.warn('reCAPTCHA action mismatch:', tokenProperties.action ?? 'missing');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
    };
  }

  const requestHostname = new URL(request.url).hostname.toLowerCase();
  const recaptchaHostname = tokenProperties.hostname?.toLowerCase();
  if (!recaptchaHostname || recaptchaHostname !== requestHostname) {
    console.warn('reCAPTCHA hostname mismatch:', recaptchaHostname ?? 'missing');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
    };
  }

  const score = parseRecaptchaScore(assessment.riskAnalysis?.score);
  if (score === null || score < getRecaptchaMinScore(env)) {
    console.warn('reCAPTCHA score below threshold:', score ?? 'missing');
    return {
      ok: false,
      message: 'reCAPTCHA verification failed. Please try again.',
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
    return renderRegisterPage(request, env, '');
  }

  const form = await readForm(request);
  const username = (form.get('username') as string | null)?.trim() ?? '';
  const email = (form.get('email') as string | null)?.trim().toLowerCase() ?? '';
  const password = (form.get('password') as string | null) ?? '';
  const confirmPassword = (form.get('confirm_password') as string | null) ?? '';

  const renderError = async (msg: string): Promise<Response> => {
    return renderRegisterPage(request, env, msg, 400);
  };

  if (!(await validateCsrf(request, form))) {
    return renderError('Your session expired. Please try again.');
  }

  if (!username || !email || !password) return renderError('All fields are required.');
  if (password !== confirmPassword) return renderError('Passwords do not match.');
  if (password.length < 15) return renderError('Password must be at least 15 characters.');
  if (password.length > MAX_PASSWORD_LENGTH) {
    return renderError(`Password must be at most ${MAX_PASSWORD_LENGTH} characters.`);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return renderError('Invalid email address.');

  if (username.length > 64 || email.length > 254) return renderError('Username or email is too long.');
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  if (!(await rlStub(env, `register:${await sha256Hex(ip)}`).consume(3600, 5))) {
    return new Response('Too many registration attempts.', { status: 429, headers: { 'Retry-After': '3600' } });
  }

  // Single generic message for both duplicate cases to avoid account enumeration.
  const [existingByUsername, existingByEmail] = await Promise.all([
    getUserByUsername(env.DB, username),
    getUserByEmail(env.DB, email),
  ]);
  if (existingByUsername || existingByEmail) {
    return renderError('That username or email is unavailable.');
  }

  const id = crypto.randomUUID();
  await createUser(env.DB, {
    id,
    username,
    email,
    password_hash: await hashPassword(password),
  });

  const previousSession = getSessionId(request);
  if (previousSession) await deleteSession(env.SESSIONS, previousSession);
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

async function renderRegisterPage(
  request: Request,
  env: Env,
  error: string,
  status = 200,
): Promise<Response> {
  const html = await loadTemplate(env, '/register.html');
  const secure = new URL(request.url).protocol === 'https:';
  const csrf = ensureCsrfToken(request, secure);
  const response = htmlResponse(
    html
      .replace('{{ERROR}}', escapeHtml(error))
      .replace('{{CSRF_TOKEN}}', escapeHtml(csrf.token)),
    status,
  );
  if (csrf.setCookie) response.headers.append('Set-Cookie', csrf.setCookie);
  return response;
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
  const csrf = ensureCsrfToken(request, url.protocol === 'https:');
  const response = htmlResponse(html.replace('{{CSRF_TOKEN}}', escapeHtml(csrf.token)));
  if (csrf.setCookie) response.headers.append('Set-Cookie', csrf.setCookie);
  return response;
}

// ---------------------------------------------------------------------------
// POST /logout
// ---------------------------------------------------------------------------

async function handleLogout(request: Request, env: Env): Promise<Response> {
  if (!(await validateCsrf(request, await readForm(request)))) return new Response('Forbidden', { status: 403 });
  const sessionId = getSessionId(request);
  if (sessionId) await deleteSession(env.SESSIONS, sessionId);

  const secure = new URL(request.url).protocol === 'https:';
  return new Response(null, {
    status: 302,
    headers: {
      'Set-Cookie': buildClearCookieHeader(secure),
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
//   New IDs/secrets are provider-generated; clientId addresses an existing client.
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

  if (!adminSecret) {
    console.error('ADMIN_SECRET is not configured – /admin/setup-clients is disabled. Set it with `wrangler secret put ADMIN_SECRET`.');
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }
  if (!provided || !(await timingSafeEqualStrings(provided, adminSecret))) {
    return Response.json({ error: 'Forbidden' }, { status: 403 });
  }

  if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json') {
    return Response.json({ error: 'Expected application/json' }, { status: 415 });
  }
  let body: unknown;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON' }, { status: 400 }); }
  if (!body || typeof body !== 'object' || !('clients' in body) || !Array.isArray(body.clients) || body.clients.length > 50) {
    return Response.json({ error: 'Provide a clients array with at most 50 entries' }, { status: 400 });
  }
  // Validate the entire batch before any client is created, updated, or deleted.
  const bodyClients: ClientDef[] = [];
  for (const value of body.clients) {
    if (!value || typeof value !== 'object') return Response.json({ error: 'Invalid client' }, { status: 400 });
    const def = value as ClientDef;
    const method = def.tokenEndpointAuthMethod ?? (def.clientSecret ? 'client_secret_post' : 'none');
    if (typeof def.clientName !== 'string' || !def.clientName.trim() || def.clientName.length > 128 ||
        (def.clientId !== undefined && (typeof def.clientId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(def.clientId))) ||
        !Array.isArray(def.redirectUris) || !def.redirectUris.length || def.redirectUris.length > 20 ||
        validateRedirectUris(def.redirectUris) ||
        !['none', 'client_secret_post', 'client_secret_basic'].includes(method) ||
        (def.clientSecret !== undefined && (typeof def.clientSecret !== 'string' || def.clientSecret.length < 32)) ||
        (method === 'none' && def.clientSecret !== undefined) ||
        (def.grantTypes !== undefined && (!Array.isArray(def.grantTypes) || !def.grantTypes.includes('authorization_code') ||
          def.grantTypes.some((grant) => !['authorization_code', 'refresh_token'].includes(grant))))) {
      return Response.json({ error: 'Invalid client metadata, redirect URI, grant type, or secret (minimum 32 characters)' }, { status: 400 });
    }
    bodyClients.push(def);
  }

  const results: Array<{ clientId: string; status: string; clientSecret?: string }> = [];

  for (const def of bodyClients) {
    try {
      const existing = def.clientId
        ? await env.OAUTH_PROVIDER.lookupClient(def.clientId)
        : null;
      if (def.clientId && !existing) {
        results.push({ clientId: def.clientId, status: 'error: unknown clientId; omit clientId to create a client' });
        continue;
      }
      if (!existing && def.clientSecret) {
        results.push({ clientId: def.clientName, status: 'error: new client secrets are generated by the provider; omit clientSecret' });
        continue;
      }

      const clientDef = {
        clientName: def.clientName,
        redirectUris: def.redirectUris,
        grantTypes: def.grantTypes ?? ['authorization_code', 'refresh_token'],
        tokenEndpointAuthMethod: def.tokenEndpointAuthMethod ?? existing?.tokenEndpointAuthMethod ?? (def.clientSecret ? 'client_secret_post' : 'none'),
        ...(def.clientSecret ? { clientSecret: def.clientSecret } : {}),
      };

      if (existing) {
        if (clientDef.tokenEndpointAuthMethod !== 'none' && !existing.clientSecret && !def.clientSecret) {
          results.push({ clientId: existing.clientId, status: 'error: provide a secret when converting a public client to confidential' });
          continue;
        }
        await env.OAUTH_PROVIDER.updateClient(existing.clientId, clientDef);
        results.push({ clientId: existing.clientId, status: 'updated' });
      } else {
        const created = await env.OAUTH_PROVIDER.createClient({
          ...(def.clientId ? { clientId: def.clientId } : {}),
          ...clientDef,
        });
        results.push({ clientId: created.clientId, status: 'created', ...(created.clientSecret ? { clientSecret: created.clientSecret } : {}) });
      }
    } catch {
      results.push({ clientId: def.clientId ?? def.clientName, status: 'error: client operation failed' });
    }
  }

  return Response.json({ results });
}

// ---------------------------------------------------------------------------
// Login rate limiting – backed by the RateLimiter Durable Object so increments
// are atomic. Three independent dimensions are tracked per attempt.
// ---------------------------------------------------------------------------

interface LoginRateLimitNames {
  ipUser: string;
  ip: string;
  user: string;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function loginRateLimitNames(request: Request, username: string): Promise<LoginRateLimitNames> {
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const user = username.toLowerCase();
  const [ipUserHash, ipHash, userHash] = await Promise.all([
    sha256Hex(`${ip}:${user}`),
    sha256Hex(ip),
    sha256Hex(user),
  ]);
  return { ipUser: `ipuser:${ipUserHash}`, ip: `ip:${ipHash}`, user: `user:${userHash}` };
}

function rlStub(env: Env, name: string) {
  return env.RATE_LIMITER.get(env.RATE_LIMITER.idFromName(name));
}

/**
 * Validate client redirect URIs to prevent token-theft via loose redirects.
 * Requires absolute https:// (http:// allowed only for localhost), and rejects
 * fragments and wildcard hosts. Returns an error message or null when valid.
 */
function validateRedirectUris(uris: unknown[]): string | null {
  for (const raw of uris) {
    if (typeof raw !== 'string' || raw.trim() === '') {
      return 'redirectUris must be non-empty strings';
    }
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return `invalid redirect URI: ${raw}`;
    }
    if (url.username || url.password || raw !== raw.trim() || raw.includes('\\')) return 'redirect URI must not contain credentials, whitespace or backslashes';
    if (raw.includes('#')) return `redirect URI must not contain a fragment: ${raw}`;
    if (url.hostname.includes('*')) return `redirect URI must not contain wildcards: ${raw}`;
    const isLocal = isLocalHost(url.hostname);
    if (url.protocol === 'https:') continue;
    if (url.protocol === 'http:' && isLocal) continue;
    return `redirect URI must use https (http allowed only for localhost): ${raw}`;
  }
  return null;
}
