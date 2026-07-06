import type { SessionData } from '../types';

const SESSION_TTL = 86_400; // 24 hours in seconds

// ---------------------------------------------------------------------------
// Session cookie helpers
// ---------------------------------------------------------------------------

// `__Host-` forces Secure + Path=/ + host-only (no Domain), preventing the
// cookie from being set/overwritten by subdomains. The prefix mandates Secure,
// so on insecure localhost dev we fall back to the unprefixed name.
const SESSION_COOKIE_SECURE = '__Host-session';
const SESSION_COOKIE_INSECURE = 'session';

export function getSessionId(request: Request): string | null {
  const cookie = request.headers.get('Cookie') ?? '';
  const match = /(?:^|;\s*)(?:__Host-)?session=([^;]+)/.exec(cookie);
  return match ? match[1] : null;
}

export function buildSetCookieHeader(sessionId: string, secure: boolean): string {
  const name = secure ? SESSION_COOKIE_SECURE : SESSION_COOKIE_INSECURE;
  const parts = [
    `${name}=${sessionId}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${SESSION_TTL}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

export function buildClearCookieHeader(secure: boolean): string {
  const name = secure ? SESSION_COOKIE_SECURE : SESSION_COOKIE_INSECURE;
  const parts = [`${name}=`, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

// ---------------------------------------------------------------------------
// KV session store
// ---------------------------------------------------------------------------

export async function getSession(
  kv: KVNamespace,
  sessionId: string,
): Promise<SessionData | null> {
  return kv.get<SessionData>(`session:${sessionId}`, 'json');
}

export async function createSession(kv: KVNamespace, data: SessionData): Promise<string> {
  const sessionId = crypto.randomUUID();
  await kv.put(`session:${sessionId}`, JSON.stringify(data), {
    expirationTtl: SESSION_TTL,
  });
  return sessionId;
}

export async function updateSession(
  kv: KVNamespace,
  sessionId: string,
  data: SessionData,
): Promise<void> {
  await kv.put(`session:${sessionId}`, JSON.stringify(data), {
    expirationTtl: SESSION_TTL,
  });
}

export async function deleteSession(kv: KVNamespace, sessionId: string): Promise<void> {
  await kv.delete(`session:${sessionId}`);
}
