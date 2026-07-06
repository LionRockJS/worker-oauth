import { OAuthProvider } from '@cloudflare/workers-oauth-provider';
import type { Env } from './types';
import { ApiHandler } from './handlers/api';
import { defaultHandler } from './handlers/default';
import { canonicalHostResponse, withSecurityHeaders } from './utils/security';

export { RateLimiter } from './durable/RateLimiter';

// ---------------------------------------------------------------------------
// OAuth 2.1 Provider – powered by @cloudflare/workers-oauth-provider
//
// The library handles:
//   - POST /oauth/token          (authorization_code + refresh_token exchange)
//   - GET  /.well-known/oauth-authorization-server  (RFC 8414 discovery)
//   - GET  /.well-known/oauth-protected-resource    (RFC 9728 metadata)
//   - Bearer token validation on configured API routes
//
// We handle:
//   - GET/POST /oauth/authorize  (consent UI)
//   - GET/POST /login            (user authentication)
//   - GET/POST /register         (user registration)
//   - GET /dashboard             (first-party web UI)
//   - GET /api/me                (session-authenticated profile API)
//   - GET /oauth/userinfo        (OAuth-protected OIDC UserInfo)
//   - POST /admin/setup-clients  (protected client seeding)
// ---------------------------------------------------------------------------

const oauthProvider = new OAuthProvider({
  // OAuth-token-protected routes → ApiHandler
  apiRoute: ['/oauth/userinfo'],
  apiHandler: ApiHandler,

  // Everything else → defaultHandler
  defaultHandler,

  // Endpoints
  authorizeEndpoint: '/oauth/authorize',
  tokenEndpoint: '/oauth/token',

  // Scopes this AS supports
  scopesSupported: ['openid', 'profile', 'email', 'roles'],

  // Security: require S256 PKCE only
  allowPlainPKCE: false,

  // Token lifetimes (library defaults: 3600s / 2592000s)
  accessTokenTTL: 3600,
  refreshTokenTTL: 2592000,
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const canonicalResponse = canonicalHostResponse(request, env.ISSUER);
    if (canonicalResponse) return withSecurityHeaders(canonicalResponse);

    return withSecurityHeaders(await oauthProvider.fetch(request, env, ctx));
  },

  // Periodic cleanup of expired tokens/grants from OAUTH_KV
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      oauthProvider.purgeExpiredData(env).then((r) => {
        console.log('OAuth KV cleanup:', JSON.stringify(r));
      }),
    );
  },
} satisfies ExportedHandler<Env>;
