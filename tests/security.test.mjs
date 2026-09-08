import { test } from 'node:test';
import assert from 'node:assert/strict';
import { timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { getCsrfCookie, validateCsrf, canonicalHostResponse, boundRequestBody, readForm } from '../src/utils/security.ts';
import { getSessionId } from '../src/handlers/session.ts';
import { validAuthorization } from '../src/utils/oauth.ts';
import { RateLimiter } from '../src/durable/RateLimiter.ts';
import { defaultHandler } from '../src/handlers/default.ts';
import { ApiHandler } from '../src/handlers/api.ts';
import worker from '../src/index.ts';

crypto.subtle.timingSafeEqual = (a, b) => timingSafeEqual(Buffer.from(a), Buffer.from(b));
const origin = 'https://id.example.com';
const sid = '11111111-1111-4111-8111-111111111111';
const csrf = 'a'.repeat(43);
const cookie = `__Host-session=${sid}; __Host-csrf=${csrf}`;
const auth = { clientId: 'app', redirectUri: 'https://app.example.com/callback', responseType: 'code', scope: ['openid'], codeChallengeMethod: 'S256', codeChallenge: 'b'.repeat(43), state: 'state' };
const client = { clientId: 'app', redirectUris: [auth.redirectUri], grantTypes: ['authorization_code', 'refresh_token'] };
function req(path, fields, headers = {}) {
  return new Request(origin + path, fields === undefined ? { headers } : {
    method: 'POST', body: new URLSearchParams(fields), headers: { Cookie: cookie, Origin: origin, ...headers },
  });
}
function kv() {
  const data = new Map();
  return { data, async get(key, options) { const raw = data.get(key) ?? null; return raw && (options === 'json' || options?.type === 'json') ? JSON.parse(raw) : raw; }, async put(k, v) { data.set(k, v); }, async delete(k) { data.delete(k); }, async list() { return { keys: [], list_complete: true }; } };
}
function limiter() {
  let state; let queue = Promise.resolve();
  const txn = { async get() { return state && structuredClone(state); }, async put(_k, v) { state = structuredClone(v); }, async setAlarm() {} };
  const storage = { ...txn, async deleteAll() { state = undefined; }, transaction(fn) { const run = queue.then(() => fn(txn)); queue = run.catch(() => {}); return run; } };
  return new RateLimiter({ storage }, {});
}
function env() {
  const sessions = kv();
  sessions.data.set(`session:${sid}`, JSON.stringify({ userId: 'user', username: 'alice' }));
  const objects = new Map();
  const counters = { complete: 0, userReads: 0, writes: 0 };
  const user = { id: 'user', username: 'alice', email: 'alice@example.com', password_hash: '', created_at: 0 };
  const e = {
    ISSUER: origin, SESSIONS: sessions, OAUTH_KV: kv(), RECAPTCHA_SITE_KEY: '', RECAPTCHA_ENFORCE: 'false',
    RATE_LIMITER: { idFromName: n => n, get(n) { if (!objects.has(n)) objects.set(n, limiter()); return objects.get(n); } },
    ASSETS: { async fetch(r) { return new Response(await readFile(new URL('../public' + new URL(r.url).pathname, import.meta.url), 'utf8')); } },
    DB: { prepare(sql) { return { bind() { return this; }, async first() { counters.userReads++; return sql.includes('users') ? e.user : null; }, async all() { return { results: [{ name: 'user' }] }; } }; } },
    OAUTH_PROVIDER: {
      async parseAuthRequest() { return structuredClone(e.auth); }, async lookupClient() { return e.client; },
      async completeAuthorization() { counters.complete++; return { redirectTo: auth.redirectUri + '?code=issued' }; },
      async unwrapToken() { return { userId: 'user', scope: e.scopes }; },
      async deleteClient() { counters.writes++; }, async createClient() { counters.writes++; return client; },
    }, auth: structuredClone(auth), client: structuredClone(client), scopes: ['openid'], user, counters,
  };
  return e;
}

test('HTTPS ignores development cookies and rejects duplicates', () => {
  assert.equal(getSessionId(req('/', undefined, { Cookie: `session=${sid}` })), null);
  assert.equal(getSessionId(req('/', undefined, { Cookie: `session=evil; ${cookie}` })), sid);
  assert.equal(getSessionId(req('/', undefined, { Cookie: `${cookie}; __Host-session=${sid}` })), null);
  assert.equal(getCsrfCookie(req('/', undefined, { Cookie: `csrf=${csrf}` })), null);
  assert.equal(getCsrfCookie(req('/', undefined, { Cookie: cookie })), csrf);
  assert.equal(getSessionId(new Request('http://localhost/', { headers: { Cookie: `session=${sid}` } })), sid);
});
test('CSRF requires valid host cookie and matching field', async () => {
  const form = new FormData(); form.set('csrf_token', csrf);
  assert.equal(await validateCsrf(req('/', undefined, { Cookie: cookie }), form), true);
  form.set('csrf_token', 'wrong');
  assert.equal(await validateCsrf(req('/', undefined, { Cookie: cookie }), form), false);
});
test('canonical redirects cannot interpret a // path as an external host', () => {
  const response = canonicalHostResponse(new Request('https://alias.example//evil.example/path?q=1'), origin);
  assert.equal(new URL(response.headers.get('Location')).origin, origin);
  assert.equal(canonicalHostResponse(new Request('https://alias.example/login', { method: 'POST' }), origin).status, 404);
});
test('body limit checks streamed bytes; form rejects duplicates and multipart', async () => {
  await assert.rejects(boundRequestBody(new Request(origin, { method: 'POST', body: 'x'.repeat(65_537) })), e => e.status === 413);
  const bounded = await boundRequestBody(req('/login', { username: 'alice' }));
  assert.equal((await readForm(bounded)).get('username'), 'alice');
  await assert.rejects(readForm(new Request(origin, { method: 'POST', body: 'x=1&x=2', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })), e => e.status === 400);
  await assert.rejects(readForm(new Request(origin, { method: 'POST', body: new FormData() })), e => e.status === 415);
});
test('authorization requires code, exact redirect, supported scopes and S256 challenge', () => {
  assert.equal(validAuthorization(auth, client), true);
  for (const patch of [{ codeChallenge: undefined }, { codeChallenge: 'short' }, { codeChallengeMethod: 'plain' }, { responseType: 'token' }, { redirectUri: auth.redirectUri + '/evil' }, { scope: ['admin'] }]) {
    assert.equal(validAuthorization({ ...auth, ...patch }, client), false);
  }
});
test('invalid authorization is rejected before creating login continuation', async () => {
  const e = env(); e.auth.codeChallenge = undefined;
  assert.equal((await defaultHandler.fetch(req('/oauth/authorize'), e)).status, 400);
  assert.equal([...e.SESSIONS.data.keys()].filter(k => k.startsWith('auth_request:')).length, 0);
});
test('rate limiter reserves at most the configured budget under concurrency', async () => {
  const r = limiter();
  const results = await Promise.all(Array.from({ length: 100 }, () => r.consume(900, 8)));
  assert.equal(results.filter(Boolean).length, 8);
});
test('parallel login attempts are limited before reCAPTCHA and password lookup', async () => {
  const e = env();
  const responses = await Promise.all(Array.from({ length: 20 }, () => defaultHandler.fetch(req('/login', { csrf_token: csrf, username: 'alice', password: 'bad', recaptcha_token: 'invalid' }), e)));
  assert.equal(responses.filter(r => r.status === 429).length, 12);
  assert.equal(e.counters.userReads, 0); // Production cannot bypass missing CAPTCHA config.
});
test('logout requires POST and CSRF; legitimate logout deletes the session', async () => {
  const e = env();
  assert.equal((await defaultHandler.fetch(req('/logout'), e)).status, 405);
  assert.equal((await defaultHandler.fetch(req('/logout', {}), e)).status, 403);
  assert.equal((await defaultHandler.fetch(req('/logout', { csrf_token: csrf }, { Origin: 'https://evil.example' }), e)).status, 403);
  assert.equal((await defaultHandler.fetch(req('/logout', { csrf_token: csrf }), e)).status, 302);
  assert.equal(e.SESSIONS.data.has(`session:${sid}`), false);
});
test('consent is session-bound and single-use even when KV retains stale data', async () => {
  const e = env();
  const stored = { req: auth, sessionId: sid, expiresAt: Date.now() + 600_000 };
  e.SESSIONS.data.set('consent_req:consent', JSON.stringify(stored));
  e.SESSIONS.delete = async () => {}; // Simulate stale KV reads after deletion.
  const submit = () => defaultHandler.fetch(req('/oauth/authorize', { csrf_token: csrf, request_id: 'consent', action: 'approve' }), e);
  const responses = await Promise.all([submit(), submit()]);
  assert.deepEqual(responses.map(r => r.status).sort(), [302, 400]);
  assert.equal(e.counters.complete, 1);
  e.SESSIONS.data.set('consent_req:consent', JSON.stringify({ ...stored, sessionId: 'other' }));
  assert.equal((await submit()).status, 403);
});
test('denial revalidates client redirect registration', async () => {
  const e = env();
  e.SESSIONS.data.set('consent_req:consent', JSON.stringify({ req: auth, sessionId: sid, expiresAt: Date.now() + 600_000 }));
  e.client.redirectUris = ['https://changed.example/callback'];
  const response = await defaultHandler.fetch(req('/oauth/authorize', { csrf_token: csrf, request_id: 'consent', action: 'deny' }), e);
  assert.equal(response.status, 400); assert.equal(response.headers.has('Location'), false);
});
test('UserInfo honors token scope and current roles; deleted users fail closed', async () => {
  const e = env(); const api = new ApiHandler({ props: { userId: 'user', roles: ['admin'] } }, e);
  const fetchInfo = () => api.fetch(req('/oauth/userinfo', undefined, { Authorization: 'Bearer test' }));
  assert.deepEqual(await (await fetchInfo()).json(), { sub: 'user' });
  e.scopes = ['openid', 'roles', 'email'];
  assert.deepEqual(await (await fetchInfo()).json(), { sub: 'user', roles: ['user'], email: 'alice@example.com', email_verified: false });
  e.scopes = ['email']; assert.equal((await fetchInfo()).status, 403);
  e.scopes = ['openid']; e.user = null; assert.equal((await fetchInfo()).status, 401);
});
test('static scripts are available but raw templates and unsupported methods are not', async () => {
  const e = env();
  assert.equal((await defaultHandler.fetch(req('/js/login.js'), e)).status, 200);
  assert.equal((await defaultHandler.fetch(req('/login.html'), e)).status, 404);
  assert.equal((await defaultHandler.fetch(new Request(origin + '/login', { method: 'PUT' }), e)).status, 405);
});
test('client setup rejects malformed metadata before any mutation', async () => {
  for (const body of ['bad json', JSON.stringify({ clients: [null] }), JSON.stringify({ clients: [{ clientName: 'app', redirectUris: ['https://u:p@app.example/cb'] }] }), JSON.stringify({ clients: [{ clientName: 'app', redirectUris: [auth.redirectUri], tokenEndpointAuthMethod: 'client_secret_post', clientSecret: 'short' }] })]) {
    const e = env(); e.ADMIN_SECRET = 'test-admin-secret';
    const response = await defaultHandler.fetch(new Request(origin + '/admin/setup-clients', { method: 'POST', headers: { 'X-Admin-Secret': e.ADMIN_SECRET, 'Content-Type': 'application/json' }, body }), e);
    assert.equal(response.status, 400); assert.equal(e.counters.writes, 0);
  }
});
test('outer error responses and redirects have security and no-store headers', async () => {
  const response = await worker.fetch(new Request('https://alias.example/login'), env(), {});
  assert.equal(response.status, 308); assert.equal(response.headers.get('Cache-Control'), 'no-store');
  assert.equal(response.headers.get('X-Frame-Options'), 'DENY');
  const oversized = await worker.fetch(new Request(origin + '/oauth/token', { method: 'POST', body: 'x'.repeat(65_537) }), env(), {});
  assert.equal(oversized.status, 413); assert.equal(oversized.headers.get('Cache-Control'), 'no-store');
});

test('real provider: authorize → consent → PKCE exchange → UserInfo → downscoped refresh', async () => {
  const { getOAuthApi } = await import('@cloudflare/workers-oauth-provider');
  const { oauthOptions } = await import('../src/index.ts');
  const { base64url } = await import('../src/utils/crypto.ts');
  const e = env(); delete e.OAUTH_PROVIDER;
  const helpers = getOAuthApi(oauthOptions, e);
  const registered = await helpers.createClient({ ...client, tokenEndpointAuthMethod: 'none', clientName: 'Test app' });
  const verifier = 'v'.repeat(43);
  const challenge = base64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  const params = new URLSearchParams({ client_id: registered.clientId, response_type: 'code', redirect_uri: auth.redirectUri,
    scope: 'openid profile email roles', code_challenge: challenge, code_challenge_method: 'S256', state: 'opaque-state' });
  const render = await worker.fetch(req('/oauth/authorize?' + params, undefined, { Cookie: cookie }), e, {});
  assert.equal(render.status, 200);
  const html = await render.text();
  const requestId = /name="request_id" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(requestId);
  const approved = await worker.fetch(req('/oauth/authorize', { csrf_token: csrf, request_id: requestId, action: 'approve' }), e, {});
  assert.equal(approved.status, 302);
  const redirect = new URL(approved.headers.get('Location'));
  assert.equal(redirect.searchParams.get('state'), 'opaque-state');
  const tokenFields = { grant_type: 'authorization_code', client_id: registered.clientId, redirect_uri: auth.redirectUri, code: redirect.searchParams.get('code'), code_verifier: verifier };
  const exchange = await worker.fetch(req('/oauth/token', tokenFields), e, {});
  assert.equal(exchange.status, 200, await exchange.clone().text());
  const tokens = await exchange.json();
  assert.equal(tokens.expires_in, 900);
  const info = await worker.fetch(req('/oauth/userinfo', undefined, { Authorization: 'Bearer ' + tokens.access_token }), e, {});
  assert.equal(info.status, 200, await info.clone().text());
  assert.deepEqual(await info.json(), { sub: 'user', preferred_username: 'alice', email: 'alice@example.com', email_verified: false, roles: ['user'] });
  const refreshed = await worker.fetch(req('/oauth/token', { grant_type: 'refresh_token', client_id: registered.clientId, refresh_token: tokens.refresh_token, scope: 'openid' }), e, {});
  assert.equal(refreshed.status, 200, await refreshed.clone().text());
  const narrow = await refreshed.json();
  const narrowInfo = await worker.fetch(req('/oauth/userinfo', undefined, { Authorization: 'Bearer ' + narrow.access_token }), e, {});
  assert.deepEqual(await narrowInfo.json(), { sub: 'user' });
  assert.equal((await worker.fetch(req('/oauth/token', tokenFields), e, {})).status, 400);
});

test('real client setup returns usable generated credentials without silently accepting fixed IDs', async () => {
  const e = env(); delete e.OAUTH_PROVIDER; e.ADMIN_SECRET = 'admin-secret';
  const setup = body => worker.fetch(new Request(origin + '/admin/setup-clients', {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Secret': e.ADMIN_SECRET }, body: JSON.stringify(body),
  }), e, {});
  const response = await setup({ clients: [{ clientName: 'Server', redirectUris: [auth.redirectUri], tokenEndpointAuthMethod: 'client_secret_post' }] });
  const created = (await response.json()).results[0];
  assert.equal(created.status, 'created'); assert.ok(created.clientSecret.length >= 32);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  const { getOAuthApi } = await import('@cloudflare/workers-oauth-provider');
  const { oauthOptions } = await import('../src/index.ts');
  const stored = await getOAuthApi(oauthOptions, e).lookupClient(created.clientId);
  assert.notEqual(stored.clientSecret, created.clientSecret); // Provider stores a hash.
  const unknown = await setup({ clients: [{ clientId: 'fixed-id', clientName: 'Server', redirectUris: [auth.redirectUri] }] });
  assert.match((await unknown.json()).results[0].status, /unknown clientId/);
});

test('registration rejects weak passwords and limits work before database lookup', async () => {
  const e = env();
  const weak = await defaultHandler.fetch(req('/register', { csrf_token: csrf, username: 'newuser', email: 'new@example.com', password: '12345678', confirm_password: '12345678' }), e);
  assert.equal(weak.status, 400); assert.equal(e.counters.userReads, 0);
  const submit = () => defaultHandler.fetch(req('/register', { csrf_token: csrf, username: 'alice', email: 'alice@example.com', password: 'long-enough-password', confirm_password: 'long-enough-password' }), e);
  for (let i = 0; i < 5; i++) assert.equal((await submit()).status, 400);
  const reads = e.counters.userReads;
  assert.equal((await submit()).status, 429); assert.equal(e.counters.userReads, reads);
});

test('real Argon2 login rotates a session and rejects another browser’s continuation', async () => {
  const { hashPassword } = await import('../src/utils/crypto.ts');
  const e = env(); e.user.password_hash = await hashPassword('a long test passphrase');
  e.SESSIONS.data.set('auth_request:other-browser', JSON.stringify({ url: 'http://localhost/oauth/authorize', csrfToken: 'z'.repeat(43), expiresAt: Date.now() + 600_000 }));
  const request = new Request('http://localhost/login', { method: 'POST',
    headers: { Cookie: `session=${sid}; csrf=${csrf}`, Origin: 'http://localhost' },
    body: new URLSearchParams({ csrf_token: csrf, username: 'alice', password: 'a long test passphrase', auth_request_id: 'other-browser' }),
  });
  const response = await defaultHandler.fetch(request, e);
  assert.equal(response.status, 302); assert.equal(response.headers.get('Location'), '/dashboard');
  assert.equal(e.SESSIONS.data.has(`session:${sid}`), false);
  assert.ok(response.headers.get('Set-Cookie').startsWith('session='));
  assert.ok(!response.headers.get('Set-Cookie').includes(sid));
});
