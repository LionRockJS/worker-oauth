import { WorkerEntrypoint } from 'cloudflare:workers';
import type { Env, UserProps } from '../types';
import { getUserById, getUserRoles } from '../db/queries';

// ---------------------------------------------------------------------------
// API handler – handles OAuth-token-protected routes
// The OAuthProvider library validates the Bearer token and injects
// the grant's props into ctx.props before forwarding here.
// ---------------------------------------------------------------------------

interface AuthorizedContext extends ExecutionContext {
  props: UserProps;
}

export class ApiHandler extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    const props = (this.ctx as AuthorizedContext).props;
    const path = new URL(request.url).pathname;

    // CORS pre-flight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Authorization',
        },
      });
    }

    // Read the token's actual scopes, including refresh-token downscoping and
    // tokens issued before this hardening update. Grant props alone are insufficient.
    if (path === '/oauth/userinfo' && request.method === 'GET') {
      const token = await this.env.OAUTH_PROVIDER.unwrapToken<UserProps>(
        (request.headers.get('Authorization') ?? '').slice(7),
      );
      if (!token || token.userId !== props.userId) {
        return Response.json({ error: 'invalid_token' }, { status: 401 });
      }
      const scopes = new Set(token.scope);
      if (!scopes.has('openid')) {
        return Response.json({ error: 'insufficient_scope' }, {
          status: 403,
          headers: { 'WWW-Authenticate': 'Bearer error="insufficient_scope", scope="openid"' },
        });
      }
      const user = await getUserById(this.env.DB, props.userId);
      if (!user) return Response.json({ error: 'invalid_token' }, { status: 401 });
      return Response.json(
        {
          sub: user.id,
          ...(scopes.has('profile') ? { preferred_username: user.username } : {}),
          ...(scopes.has('email') ? { email: user.email, email_verified: false } : {}),
          ...(scopes.has('roles') ? { roles: await getUserRoles(this.env.DB, user.id) } : {}),
        },
        {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store',
          },
        },
      );
    }

    return new Response('Not Found', { status: 404 });
  }
}
