/**
 * Type declarations for WebAssembly module imports (wrangler bundles *.wasm
 * files as pre-compiled WebAssembly.Module objects at build time).
 */
declare module '*.wasm' {
  const mod: WebAssembly.Module;
  export default mod;
}

/**
 * Minimal types for the argon2id package's internal setup helper.
 * We use the custom-loader API so that we can pass pre-compiled
 * WebAssembly.Module objects (as provided by wrangler) instead of the
 * callable loaders that rollup-plugin-wasm / wasm-loader would produce.
 */
declare module 'argon2id/lib/setup.js' {
  export type Argon2idParams = {
    password: Uint8Array;
    salt: Uint8Array;
    parallelism: number;
    /** Number of iterations */
    passes: number;
    /** Memory cost in kibibytes */
    memorySize: number;
    /** Output hash length in bytes */
    tagLength: number;
    ad?: Uint8Array;
    secret?: Uint8Array;
  };

  export type ComputeHash = (params: Argon2idParams) => Uint8Array;

  type WasmLoader = (
    importObject: WebAssembly.Imports,
  ) => Promise<{ instance: WebAssembly.Instance }>;

  export default function setupWasm(
    getSIMD: WasmLoader,
    getNonSIMD: WasmLoader,
  ): Promise<ComputeHash>;
}
