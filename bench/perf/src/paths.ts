import { join, resolve } from "node:path";

/** bench/perf */
export const TOOL_ROOT: string = resolve(import.meta.dirname, "..");
/** Repository root (hpke-js) */
export const REPO_ROOT: string = resolve(TOOL_ROOT, "../..");
/** Output directory for the generated bundles. */
export const DIST: string = join(TOOL_ROOT, "dist");
