import { generateToken } from './crypto';

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': [
    "default-src 'self'",
    // No 'unsafe-inline'/'unsafe-eval': all first-party scripts are external
    // files served from 'self'. Google origins are required by reCAPTCHA.
    "script-src 'self' https://www.google.com https://www.gstatic.com",
    // 'unsafe-inline' retained for styles only — reCAPTCHA injects inline
    // styles for its badge/challenge; style injection is low risk.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "connect-src 'self' https://www.google.com https://www.recaptcha.net",
    "frame-src https://www.google.com https://recaptcha.google.com https://www.recaptcha.net",
    "form-action 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
};

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// ---------------------------------------------------------------------------
// CSRF – double-submit cookie. A random token is set in a host-only cookie on
// GET renders and mirrored into a hidden form field; mutating POSTs must echo
// a matching token. Combined with the Origin check and SameSite=Lax cookies
// this gives layered CSRF protection independent of the reCAPTCHA flow.
// ---------------------------------------------------------------------------

const CSRF_COOKIE_SECURE = '__Host-csrf';
const CSRF_COOKIE_INSECURE = 'csrf';
const CSRF_COOKIE_TTL = 3600;

export function getCsrfCookie(request: Request): string | null {
  const value = readHostCookie(request, 'csrf');
  return value && /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

/** Never accept development cookies on HTTPS, or ambiguous duplicate cookies. */
export function readHostCookie(request: Request, name: string): string | null {
  const secure = new URL(request.url).protocol === 'https:';
  const expected = secure ? `__Host-${name}` : name;
  const values = (request.headers.get('Cookie') ?? '').split(';')
    .map((part) => part.trim()).filter((part) => part.startsWith(`${expected}=`));
  return values.length === 1 ? values[0].slice(expected.length + 1) : null;
}

export function buildCsrfCookie(token: string, secure: boolean): string {
  const name = secure ? CSRF_COOKIE_SECURE : CSRF_COOKIE_INSECURE;
  const parts = [`${name}=${token}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${CSRF_COOKIE_TTL}`];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

/**
 * Return the CSRF token to embed in a form, reusing the existing cookie token
 * when present. `setCookie` is non-null only when a fresh cookie must be set.
 */
export function ensureCsrfToken(request: Request, secure: boolean): { token: string; setCookie: string | null } {
  const existing = getCsrfCookie(request);
  if (existing) return { token: existing, setCookie: null };
  const token = generateToken();
  return { token, setCookie: buildCsrfCookie(token, secure) };
}

export async function validateCsrf(request: Request, form: FormData): Promise<boolean> {
  const cookieToken = getCsrfCookie(request);
  const field = form.get('csrf_token');
  const formToken = typeof field === 'string' ? field : '';
  if (!cookieToken || !formToken) return false;
  return timingSafeEqualStrings(formToken, cookieToken);
}

export function withSecurityHeaders(response: Response): Response {
  const secured = new Response(response.body, response);
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    secured.headers.set(name, value);
  }
  secured.headers.set('Cache-Control', 'no-store');
  secured.headers.set('Pragma', 'no-cache');
  return secured;
}

export function canonicalHostResponse(request: Request, canonicalOrigin: string): Response | null {
  const url = new URL(request.url);
  if (isLocalHost(url.hostname)) return null;

  const canonical = new URL(canonicalOrigin);
  if (url.origin === canonical.origin) return null;

  if (request.method === 'GET' || request.method === 'HEAD') {
    const redirectUrl = new URL(canonical.origin);
    redirectUrl.pathname = url.pathname;
    redirectUrl.search = url.search;
    return Response.redirect(redirectUrl.toString(), 308);
  }

  return new Response('Not Found', { status: 404 });
}

export class RequestInputError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

/** Bound bytes actually read, including chunked requests without Content-Length. */
export async function boundRequestBody(request: Request, maxBytes = 65_536): Promise<Request> {
  if (!request.body) return request;
  if (Number(request.headers.get('Content-Length')) > maxBytes) {
    throw new RequestInputError(413, 'Request body too large');
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maxBytes) {
      await reader.cancel();
      throw new RequestInputError(413, 'Request body too large');
    }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return new Request(request, { body });
}

export async function readForm(request: Request): Promise<FormData> {
  if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/x-www-form-urlencoded') {
    throw new RequestInputError(415, 'Expected a URL-encoded form');
  }
  let form: FormData;
  try { form = await request.formData(); }
  catch { throw new RequestInputError(400, 'Invalid form'); }
  for (const key of form.keys()) {
    if (form.getAll(key).length !== 1 || typeof form.get(key) !== 'string') {
      throw new RequestInputError(400, 'Duplicate or invalid form field');
    }
  }
  return form;
}

export function rejectCrossOriginMutation(request: Request): Response | null {
  if (SAFE_METHODS.has(request.method.toUpperCase())) return null;

  const url = new URL(request.url);
  const origin = request.headers.get('Origin');

  // When an Origin header is present it must match this origin. `Origin: null`
  // (sandboxed/opaque contexts) is treated as cross-origin and rejected — the
  // first-party login/consent flows always submit from this origin. Requests
  // with no Origin header at all (non-browser clients) fall through to the
  // CSRF-token check enforced by the route handlers.
  if (origin && origin !== url.origin) {
    return new Response('Forbidden', { status: 403 });
  }

  return null;
}

export async function timingSafeEqualStrings(provided: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest('SHA-256', encoder.encode(provided)),
    crypto.subtle.digest('SHA-256', encoder.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(providedHash, expectedHash);
}

export function isLocalHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]';
}
