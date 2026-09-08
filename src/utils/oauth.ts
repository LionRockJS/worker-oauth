import type { AuthRequest, ClientInfo } from '@cloudflare/workers-oauth-provider';

export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'roles'];

/** Private provider policy, enforced before login, consent, and either redirect. */
export function validAuthorization(req: AuthRequest, client: ClientInfo | null): boolean {
  return !!client && req.responseType === 'code' && !!req.clientId &&
    client.redirectUris.includes(req.redirectUri) &&
    (!client.grantTypes || client.grantTypes.includes('authorization_code')) &&
    req.codeChallengeMethod === 'S256' && /^[A-Za-z0-9_-]{43}$/.test(req.codeChallenge ?? '') &&
    req.scope.every((scope) => SUPPORTED_SCOPES.includes(scope));
}

export function hasDuplicateOAuthParameters(url: URL): boolean {
  return [...url.searchParams.keys()].some((key) => key !== 'resource' && url.searchParams.getAll(key).length > 1);
}
