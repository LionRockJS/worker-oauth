import type { Env } from '../types';
import { getKeys } from '../utils/jwt';
import type { JWKSPublicKey } from '../utils/jwt';

// ---------------------------------------------------------------------------
// OAuth 2.1 / OpenID Connect discovery document
// ---------------------------------------------------------------------------

export async function handleDiscovery(env: Env, baseUrl: URL): Promise<Response> {
  const issuer = env.ISSUER;
  const base = issuer.replace(/\/$/, '');

  const document = {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'none',
    ],
    jwks_uri: `${base}/.well-known/jwks.json`,
    revocation_endpoint: `${base}/oauth/revoke`,
    introspection_endpoint: `${base}/oauth/introspect`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'profile', 'email', 'roles'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    // OAuth 2.1 mandates PKCE for all public clients
    require_pkce: true,
    // Registration (dynamic, not supported – use pre-registered clients)
    registration_endpoint: null,
  };

  // Suppress TS warning about unused param – baseUrl kept for future use
  void baseUrl;

  return jsonResponse(document);
}

// ---------------------------------------------------------------------------
// JSON Web Key Set (JWKS)
// ---------------------------------------------------------------------------

export async function handleJWKS(env: Env): Promise<Response> {
  const keys = await getKeys(env);
  const jwks: { keys: JWKSPublicKey[] } = { keys: [keys.publicJwk] };
  return jsonResponse(jwks, {
    'Cache-Control': 'public, max-age=3600',
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(
  body: unknown,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      ...extraHeaders,
    },
  });
}
