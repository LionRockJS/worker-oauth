import type { Env } from './types';
import { handleDiscovery, handleJWKS } from './handlers/discovery';
import { handleAuthorizeGet, handleAuthorizePost } from './handlers/auth';
import { handleToken, handleRevoke, handleIntrospect } from './handlers/token';
import {
  handleLogin,
  handleRegister,
  handleDashboard,
  handleLogout,
  handleApiMe,
  handleApiToken,
} from './handlers/ui';

// ---------------------------------------------------------------------------
// Main Cloudflare Worker entry point
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname: path } = url;
    const method = request.method.toUpperCase();

    try {
      // ------------------------------------------------------------------
      // CORS pre-flight for token / introspect / revoke / JWKS endpoints
      // ------------------------------------------------------------------
      if (method === 'OPTIONS') {
        return new Response(null, {
          status: 204,
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Authorization, Content-Type',
            'Access-Control-Max-Age': '86400',
          },
        });
      }

      // ------------------------------------------------------------------
      // OAuth 2.1 / OpenID Connect discovery
      // ------------------------------------------------------------------
      if (path === '/.well-known/oauth-authorization-server' && method === 'GET') {
        return handleDiscovery(env, url);
      }
      if (path === '/.well-known/jwks.json' && method === 'GET') {
        return handleJWKS(env);
      }

      // ------------------------------------------------------------------
      // OAuth endpoints
      // ------------------------------------------------------------------
      if (path === '/oauth/authorize') {
        if (method === 'GET') return handleAuthorizeGet(request, env, url);
        if (method === 'POST') return handleAuthorizePost(request, env, url);
      }
      if (path === '/oauth/token' && method === 'POST') {
        return handleToken(request, env);
      }
      if (path === '/oauth/revoke' && method === 'POST') {
        return handleRevoke(request, env);
      }
      if (path === '/oauth/introspect' && method === 'POST') {
        return handleIntrospect(request, env);
      }

      // ------------------------------------------------------------------
      // UI routes
      // ------------------------------------------------------------------
      if (path === '/') {
        return Response.redirect(new URL('/dashboard', url).toString(), 302);
      }
      if (path === '/login') {
        return handleLogin(request, env, url);
      }
      if (path === '/register') {
        return handleRegister(request, env, url);
      }
      if (path === '/dashboard') {
        return handleDashboard(request, env, url);
      }
      if (path === '/logout') {
        return handleLogout(request, env, url);
      }

      // ------------------------------------------------------------------
      // JSON API (consumed by dashboard vanilla JS)
      // ------------------------------------------------------------------
      if (path === '/api/me' && method === 'GET') {
        return handleApiMe(request, env);
      }
      if (path === '/api/token' && method === 'POST') {
        return handleApiToken(request, env);
      }

      // ------------------------------------------------------------------
      // Fall-through: pass static assets to the Workers Assets binding
      // ------------------------------------------------------------------
      return env.ASSETS.fetch(request);
    } catch (err) {
      console.error('Unhandled error:', err);
      return new Response(
        JSON.stringify({ error: 'server_error', error_description: 'An unexpected error occurred' }),
        {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }
  },
} satisfies ExportedHandler<Env>;
