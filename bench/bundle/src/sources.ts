/**
 * Resolution of `@hpke/*` packages to the repository sources.
 *
 * `@hpke/*` packages are bundled directly from `packages/<name>/mod.ts` so
 * that the numbers always reflect the current working tree. To behave exactly
 * like the published npm packages, the `sideEffects` value that each package
 * declares in its npm `package.json` (configured in `packages/<name>/dnt.ts`)
 * is applied to every module of that package through each bundler's official
 * per-module side effects hook.
 *
 * Third-party dependencies (`hpke`, `@panva/hpke-noble`, `mlkem`, `@noble/*`)
 * are resolved from `node_modules` as usual, where each bundler reads their
 * `package.json` `sideEffects` field by itself.
 */

import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { REPO_ROOT } from "./paths.ts";

const PACKAGES_DIR = join(REPO_ROOT, "packages");

/** Error message used when the all-in-one package is imported. */
export const HPKE_JS_FORBIDDEN =
  "@hpke/hpke-js must not be used; use @hpke/core + extensions";

/** `@hpke/<name>` (bare specifier) */
export const HPKE_SPECIFIER: RegExp = /^@hpke\/([a-z0-9-]+)$/;

/** JSR import used inside the repository, mapped to its npm distribution. */
export const NPM_ALIASES: Readonly<Record<string, string>> = {
  "@dajiaji/bhttp": "bhttp-js",
  "@dajiaji/mlkem": "mlkem",
};

/** Modules that may be referenced for legacy runtimes; never bundled. */
export const EXTERNALS: readonly string[] = ["crypto", "node:crypto"];

/** Resolves `@hpke/<name>` to `packages/<name>/mod.ts`. */
export function hpkeEntryPath(name: string): string {
  return join(PACKAGES_DIR, name, "mod.ts");
}

/** Returns the package name if `path` is inside `packages/<name>/`. */
export function hpkePackageOf(path: string): string | undefined {
  const rel = relative(PACKAGES_DIR, path);
  if (rel.startsWith("..") || rel === "") return undefined;
  return rel.split(sep)[0];
}

const sideEffectsCache = new Map<string, boolean>();

/**
 * The `sideEffects` value of the npm package built from `packages/<name>`,
 * read from its `dnt.ts`. Defaults to `true` (the npm default) if absent.
 */
export function hpkeSideEffects(name: string): boolean {
  let value = sideEffectsCache.get(name);
  if (value === undefined) {
    let src = "";
    try {
      src = readFileSync(join(PACKAGES_DIR, name, "dnt.ts"), "utf8");
    } catch {
      // no dnt.ts
    }
    value = /sideEffects:\s*false\b/.test(src) ? false : true;
    sideEffectsCache.set(name, value);
  }
  return value;
}
