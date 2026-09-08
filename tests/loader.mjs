// Node test adapter: transpile application TS, load real Argon2 WASM, and stub
// only the Workers base classes. This is not a replacement for workerd testing.
import ts from 'typescript';
import { readFile } from 'node:fs/promises';
export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'cloudflare:workers') return { url: 'test:workers', shortCircuit: true };
  try { return await nextResolve(specifier, context); }
  catch (error) {
    if (specifier.startsWith('.') && !specifier.endsWith('.ts')) return nextResolve(specifier + '.ts', context);
    throw error;
  }
}
export async function load(url, context, nextLoad) {
  if (url === 'test:workers') return { format: 'module', shortCircuit: true, source: `
    export class WorkerEntrypoint { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }
    export class DurableObject extends WorkerEntrypoint {}
  ` };
  if (url.endsWith('.wasm')) {
    const bytes = await readFile(new URL(url));
    return { format: 'module', shortCircuit: true, source: `export default new WebAssembly.Module(Buffer.from('${bytes.toString('base64')}', 'base64'));` };
  }
  if (url.endsWith('.ts')) return {
    format: 'module', shortCircuit: true,
    source: ts.transpileModule(await readFile(new URL(url), 'utf8'), {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 },
    }).outputText,
  };
  return nextLoad(url, context);
}
