/**
 * Bundles the generated adapter entry points with esbuild.
 *
 * `@hpke/*` packages are bundled directly from `packages/<name>/mod.ts` so
 * that the numbers always reflect the current working tree. Third-party
 * dependencies (`hpke`, `@panva/hpke-noble`, `mlkem`, `@noble/*`) are resolved
 * from `node_modules`. Both libraries go through the same pipeline. The output
 * is not minified and not down-leveled (`target=esnext`), so that the bundler
 * does not change the runtime characteristics of either library.
 */

import * as esbuild from "esbuild";
import { dirname, join, relative, resolve, sep } from "node:path";

import { REPO_ROOT, TOOL_ROOT } from "./paths.ts";

const PACKAGES_DIR = join(REPO_ROOT, "packages");

/** JSR imports used inside the repository, mapped to their npm distribution. */
const NPM_ALIASES: Readonly<Record<string, string>> = {
  "@dajiaji/mlkem": "mlkem",
};

/** Modules that may be referenced for legacy runtimes; never bundled. */
const EXTERNALS: readonly string[] = ["crypto", "node:crypto"];

function hpkePackageOf(path: string): string | undefined {
  const rel = relative(PACKAGES_DIR, path);
  if (rel.startsWith("..") || rel === "") return undefined;
  return rel.split(sep)[0];
}

const escapeRegExp = (s: string): string =>
  s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Resolves `@hpke/<name>` to `packages/<name>/mod.ts`. */
const hpkeSources: esbuild.Plugin = {
  name: "hpke-sources",
  setup(build) {
    build.onResolve({ filter: /^@hpke\/hpke-js$/ }, () => ({
      errors: [{
        text: "@hpke/hpke-js must not be used; use @hpke/core + extensions",
      }],
    }));
    build.onResolve({ filter: /^@hpke\/([a-z0-9-]+)$/ }, (args) => ({
      path: join(PACKAGES_DIR, args.path.slice("@hpke/".length), "mod.ts"),
    }));
    // Relative imports inside packages/<name>/
    build.onResolve({ filter: /^\.\.?\// }, (args) => {
      if (hpkePackageOf(args.importer) === undefined) return undefined;
      return { path: resolve(dirname(args.importer), args.path) };
    });
    for (const [from, to] of Object.entries(NPM_ALIASES)) {
      build.onResolve(
        { filter: new RegExp(`^${escapeRegExp(from)}$`) },
        (args) => build.resolve(to, { kind: args.kind, resolveDir: TOOL_ROOT }),
      );
    }
  },
};

export const BUILD_DESCRIPTION =
  `esbuild@${esbuild.version} (bundle, format=esm, target=esnext, no minify)`;

/** Bundles an ESM entry point source into a single ESM module. */
export async function bundle(source: string): Promise<Uint8Array> {
  const result = await esbuild.build({
    stdin: { contents: source, resolveDir: TOOL_ROOT, loader: "js" },
    bundle: true,
    format: "esm",
    platform: "neutral",
    mainFields: ["module", "main"],
    target: "esnext",
    minify: false,
    write: false,
    legalComments: "none",
    logLevel: "silent",
    external: [...EXTERNALS],
    plugins: [hpkeSources],
  });
  return result.outputFiles[0].contents;
}
