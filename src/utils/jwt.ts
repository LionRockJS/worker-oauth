import { base64url, base64urlDecode } from './crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JWTPayload {
  /** Issuer */
  iss: string;
  /** Subject (user ID) */
  sub: string;
  /** Audience (client ID or array) */
  aud: string | string[];
  /** Expiration time (Unix seconds) */
  exp: number;
  /** Issued at (Unix seconds) */
  iat: number;
  /** JWT ID – also stored in the DB for revocation checks */
  jti: string;
  /** User roles included in every access token */
  roles?: string[];
  /** Granted OAuth scopes */
  scope?: string;
  /** The OAuth client that requested the token */
  client_id?: string;
  [key: string]: unknown;
}

export interface JWKSPublicKey {
  kty: string;
  use: string;
  alg: string;
  kid: string;
  n: string;
  e: string;
}

// ---------------------------------------------------------------------------
// Internal key cache (per isolate)
// ---------------------------------------------------------------------------

interface KeyCache {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kid: string;
  publicJwk: JWKSPublicKey;
}

let keyCache: KeyCache | null = null;

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

async function importPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
}

async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    true,
    ['verify'],
  );
}

/** Generate a new 2048-bit RSA key pair and return base64-encoded JWK strings. */
export async function generateKeyPair(): Promise<{
  privateKey: string;
  publicKey: string;
  kid: string;
}> {
  const pair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  const kid = crypto.randomUUID();

  return {
    privateKey: btoa(JSON.stringify(privateJwk)),
    publicKey: btoa(JSON.stringify(publicJwk)),
    kid,
  };
}

// ---------------------------------------------------------------------------
// getKeys – resolve signing keys from env secrets or KV (auto-generates on
// first run when neither source has keys, handy for local development).
// ---------------------------------------------------------------------------

export async function getKeys(env: {
  JWT_PRIVATE_KEY?: string;
  JWT_PUBLIC_KEY?: string;
  JWT_KID?: string;
  SESSIONS: KVNamespace;
}): Promise<KeyCache> {
  if (keyCache) return keyCache;

  let privateJwk: JsonWebKey;
  let publicJwk: JsonWebKey;
  let kid: string;

  if (env.JWT_PRIVATE_KEY && env.JWT_PUBLIC_KEY) {
    // Prefer secrets injected via `wrangler secret put`
    privateJwk = JSON.parse(atob(env.JWT_PRIVATE_KEY)) as JsonWebKey;
    publicJwk = JSON.parse(atob(env.JWT_PUBLIC_KEY)) as JsonWebKey;
    kid = env.JWT_KID ?? 'env-key';
  } else {
    // Fall back to KV storage (dev convenience)
    const stored = await env.SESSIONS.get<{
      privateKey: string;
      publicKey: string;
      kid: string;
    }>('jwt_keys', 'json');

    if (stored) {
      privateJwk = JSON.parse(atob(stored.privateKey)) as JsonWebKey;
      publicJwk = JSON.parse(atob(stored.publicKey)) as JsonWebKey;
      kid = stored.kid;
    } else {
      // First-run: auto-generate and persist in KV
      const generated = await generateKeyPair();
      privateJwk = JSON.parse(atob(generated.privateKey)) as JsonWebKey;
      publicJwk = JSON.parse(atob(generated.publicKey)) as JsonWebKey;
      kid = generated.kid;
      await env.SESSIONS.put('jwt_keys', JSON.stringify(generated));
    }
  }

  const privateKey = await importPrivateKey(privateJwk);
  const publicKey = await importPublicKey(publicJwk);
  const publicJwkForCache: JWKSPublicKey = {
    kty: 'RSA',
    use: 'sig',
    alg: 'RS256',
    kid,
    n: publicJwk.n!,
    e: publicJwk.e!,
  };

  keyCache = { privateKey, publicKey, kid, publicJwk: publicJwkForCache };
  return keyCache;
}

// ---------------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------------

/** Create a signed RS256 JWT. */
export async function signJWT(
  payload: JWTPayload,
  privateKey: CryptoKey,
  kid: string,
): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${base64url(signature)}`;
}

/** Verify an RS256 JWT and return its payload (throws on invalid / expired). */
export async function verifyJWT(
  token: string,
  publicKey: CryptoKey,
): Promise<JWTPayload> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const valid = await crypto.subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    base64urlDecode(encodedSignature),
    new TextEncoder().encode(signingInput),
  );

  if (!valid) throw new Error('Invalid JWT signature');

  const payload = JSON.parse(
    new TextDecoder().decode(base64urlDecode(encodedPayload)),
  ) as JWTPayload;

  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error('JWT expired');
  }

  return payload;
}
