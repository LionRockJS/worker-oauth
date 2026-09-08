import { OAuthProvider, getOAuthApi, type OAuthProviderOptions } from '@cloudflare/workers-oauth-provider';
import type { Env } from './types';
import { ApiHandler } from './handlers/api';
import { defaultHandler } from './handlers/default';
import { boundRequestBody, canonicalHostResponse, RequestInputError, withSecurityHeaders } from './utils/security';
import { SUPPORTED_SCOPES } from './utils/oauth';

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

export const oauthOptions = {
  // OAuth-token-protected routes → ApiHandler
  apiRoute: ['/oauth/userinfo'],
  apiHandler: ApiHandler,

  // Everything else → defaultHandler
  defaultHandler,

  // Endpoints
  authorizeEndpoint: '/oauth/authorize',
  tokenEndpoint: '/oauth/token',

  // Scopes this AS supports
  scopesSupported: SUPPORTED_SCOPES,

  // Security: require S256 PKCE only
  allowPlainPKCE: false,
  allowImplicitFlow: false,
  clientIdMetadataDocumentEnabled: false,

  // Token lifetimes (library defaults: 3600s / 2592000s)
  accessTokenTTL: 900,
  refreshTokenTTL: 2592000,
} satisfies OAuthProviderOptions<Env>;
const oauthProvider = new OAuthProvider(oauthOptions);

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const canonicalResponse = canonicalHostResponse(request, env.ISSUER);
      if (canonicalResponse) return withSecurityHeaders(canonicalResponse);
      if (request.url.length > 8192) throw new RequestInputError(414, 'Request URL too long');
      request = await boundRequestBody(request);
      // The library injects helpers only on default routes, not API routes.
      // Use a request-local env so UserInfo also has the supported token API.
      env = { ...env, OAUTH_PROVIDER: getOAuthApi(oauthOptions, env) };
      return withSecurityHeaders(await oauthProvider.fetch(request, env, ctx));
    } catch (error) {
      if (error instanceof RequestInputError) {
        return withSecurityHeaders(new Response(error.message, { status: error.status }));
      }
      // Do not log exception messages: upstream errors may contain credentials or URLs.
      console.error(JSON.stringify({ event: 'request_failed' }));
      return withSecurityHeaders(new Response('Internal Server Error', { status: 500 }));
    }
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
