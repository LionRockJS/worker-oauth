import type { Env } from '../types';

// ---------------------------------------------------------------------------
// Helpers – exported so default.ts can import them
// ---------------------------------------------------------------------------

export async function loadTemplate(env: Env, path: string): Promise<string> {
  const response = await env.ASSETS.fetch(new Request(`https://assets.internal${path}`));
  if (!response.ok) throw new Error(`Asset not found: ${path}`);
  return response.text();
}

export function htmlResponse(html: string, status = 200): Response {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
