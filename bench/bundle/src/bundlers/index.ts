import { esbuildBundler } from "./esbuild.ts";
import { rollupBundler } from "./rollup.ts";
import type { Bundler } from "./types.ts";

export type { BundleOutput, Bundler, BundlerId } from "./types.ts";

export const BUNDLERS: readonly Bundler[] = [esbuildBundler, rollupBundler];
