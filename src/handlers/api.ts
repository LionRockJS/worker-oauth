import { WorkerEntrypoint } from 'cloudflare:workers';
import type { Env, UserProps } from '../types';

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

    // GET /oauth/userinfo – standard OIDC UserInfo endpoint (RFC 9068)
    if (path === '/oauth/userinfo' && request.method === 'GET') {
      return Response.json(
        {
          sub: props.userId,
          preferred_username: props.username,
          email: props.email,
          roles: props.roles,
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
