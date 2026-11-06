export type BundlerId = "esbuild" | "rollup";

export interface BundleOutput {
  /** Minified ESM output. */
  code: Uint8Array;
  /**
   * Bytes in the minified output per source module, largest first.
   * Only available when the bundler can attribute minified bytes to modules.
   */
  modules?: Record<string, number>;
}

export interface Bundler {
  readonly id: BundlerId;
  /** Human readable description of the toolchain and its versions. */
  readonly description: string;
  /** Bundles an ESM entry point source (minified, tree-shaken). */
  bundle(source: string): Promise<BundleOutput>;
}
