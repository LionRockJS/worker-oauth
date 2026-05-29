import setupWasm, { type ComputeHash } from 'argon2id/lib/setup.js';
// Wrangler bundles these as pre-compiled WebAssembly.Module objects at build time.
import simdWasm from 'argon2id/dist/simd.wasm';
import nonSimdWasm from 'argon2id/dist/no-simd.wasm';

// ---------------------------------------------------------------------------
// Argon2id – initialised once per isolate lifetime.
// Using the custom-loader API so wrangler's WebAssembly.Module objects are
// passed to WebAssembly.instantiate() directly (no dynamic compilation).
// ---------------------------------------------------------------------------
const ARGON2_M = 19456; // memory cost in KiB (19 MiB – OWASP minimum)
const ARGON2_T = 2;     // iterations
const ARGON2_P = 1;     // parallelism
const ARGON2_TAG = 32;  // output bytes

const argon2idReady: Promise<ComputeHash> = setupWasm(
  async (io) => ({ instance: await WebAssembly.instantiate(simdWasm, io) }),
  async (io) => ({ instance: await WebAssembly.instantiate(nonSimdWasm, io) }),
);

/**
 * Encode a string, ArrayBuffer, or Uint8Array as a base64url string.
 */
export function base64url(data: string | ArrayBuffer | Uint8Array): string {
  let bytes: Uint8Array;
  if (typeof data === 'string') {
    bytes = new TextEncoder().encode(data);
  } else if (data instanceof ArrayBuffer) {
    bytes = new Uint8Array(data);
  } else {
    bytes = data;
  }

  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url string to a Uint8Array.
 */
export function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Hash a password with Argon2id (OWASP-recommended parameters).
 * Returns a PHC-style string:
 *   `$argon2id$v=19$m=<m>,t=<t>,p=<p>$<base64url-salt>$<base64url-hash>`
 */
export async function hashPassword(password: string): Promise<string> {
  const fn = await argon2idReady;
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = fn({
    password: new TextEncoder().encode(password),
    salt,
    parallelism: ARGON2_P,
    passes: ARGON2_T,
    memorySize: ARGON2_M,
    tagLength: ARGON2_TAG,
  });
  return `$argon2id$v=19$m=${ARGON2_M},t=${ARGON2_T},p=${ARGON2_P}$${base64url(salt)}$${base64url(hash)}`;
}

/**
 * Verify a password against a stored hash.
 * Supports the Argon2id PHC-style format produced by `hashPassword`, and the
 * legacy `pbkdf2:…` format so existing accounts keep working until their
 * password is next re-set.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  if (stored.startsWith('$argon2id$')) {
    // $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
    const parts = stored.split('$');
    // parts: [ '', 'argon2id', 'v=19', 'm=…,t=…,p=…', '<salt>', '<hash>' ]
    if (parts.length !== 6) return false;
    const paramParts = parts[3].split(',');
    const m = parseInt(paramParts[0].slice(2), 10);
    const t = parseInt(paramParts[1].slice(2), 10);
    const p = parseInt(paramParts[2].slice(2), 10);
    const salt = base64urlDecode(parts[4]);
    const storedHash = base64urlDecode(parts[5]);

    const fn = await argon2idReady;
    const hash = fn({
      password: new TextEncoder().encode(password),
      salt,
      parallelism: p,
      passes: t,
      memorySize: m,
      tagLength: storedHash.length,
    });
    return crypto.subtle.timingSafeEqual(hash, storedHash);
  }

  // Legacy PBKDF2 hashes — kept for backward compatibility
  const parts = stored.split(':');
  if (parts.length !== 3 || parts[0] !== 'pbkdf2') return false;
  const [, saltHex, hashHex] = parts;

  const salt = new Uint8Array(saltHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
  const expectedBytes = new Uint8Array(hashHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    256,
  );

  return crypto.subtle.timingSafeEqual(new Uint8Array(derivedBits), expectedBytes);
}

/**
 * Verify a PKCE code verifier against a previously stored code challenge.
 * Supports S256 (recommended) and plain methods.
 */
export async function verifyPKCE(
  codeVerifier: string,
  codeChallenge: string,
  method: string,
): Promise<boolean> {
  if (method === 'S256') {
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(codeVerifier),
    );
    return base64url(digest) === codeChallenge;
  }
  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  }
  return false;
}

/**
 * Generate a cryptographically random opaque token encoded as base64url.
 * Default length produces 256 bits of entropy.
 */
export function generateToken(byteLength = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)));
}
