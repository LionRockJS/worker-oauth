import type { SessionData } from '../types';

const SESSION_TTL = 86_400; // 24 hours in seconds

// ---------------------------------------------------------------------------
// Session cookie helpers
// ---------------------------------------------------------------------------

export function getSessionId(request: Request): string | null {
  const cookie = request.headers.get('Cookie') ?? '';
  const match = /(?:^|;\s*)session=([^;]+)/.exec(cookie);
  return match ? match[1] : null;
}

export function buildSetCookieHeader(sessionId: string, secure: boolean): string {
  const parts = [
    `session=${sessionId}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${SESSION_TTL}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

export function buildClearCookieHeader(): string {
  return 'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0';
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
