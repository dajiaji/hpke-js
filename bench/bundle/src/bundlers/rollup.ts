/**
 * rollup + @rollup/plugin-node-resolve + @rollup/plugin-terser, ESM.
 *
 * `@hpke/*` sources are TypeScript; they are stripped to JavaScript with
 * `esbuild.transform` (types only, no minification or down-leveling beyond
 * the target), which is what common rollup TypeScript setups do (e.g.
 * rollup-plugin-esbuild). Tree-shaking and minification are done entirely by
 * rollup and terser.
 */

import { nodeResolve } from "@rollup/plugin-node-resolve";
import terserModule from "@rollup/plugin-terser";
import * as esbuild from "esbuild";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { rollup, VERSION as ROLLUP_VERSION } from "rollup";
import type { Plugin } from "rollup";

import { TOOL_ROOT } from "../paths.ts";
import {
  EXTERNALS,
  HPKE_JS_FORBIDDEN,
  HPKE_SPECIFIER,
  hpkeEntryPath,
  hpkePackageOf,
  hpkeSideEffects,
  NPM_ALIASES,
} from "../sources.ts";
import { TARGET } from "./esbuild.ts";
import type { BundleOutput, Bundler } from "./types.ts";

const ENTRY_ID = "\0entry.js";

// @rollup/plugin-terser ships ESM-style type declarations in a package
// without `"type": "module"`, so under `nodenext` TypeScript sees the default
// import as the CJS module object. At runtime (ESM) it is the function.
const terser = terserModule as unknown as typeof terserModule.default;

// Warnings that are noise for this benchmark (third-party sources).
const IGNORED_WARNINGS = new Set(["CIRCULAR_DEPENDENCY", "INVALID_ANNOTATION"]);

const require = createRequire(import.meta.url);
const version = (pkg: string): string =>
  (require(join(TOOL_ROOT, "node_modules", pkg, "package.json")) as {
    version: string;
  }).version;

function hpkeSources(entrySource: string): Plugin {
  return {
    name: "hpke-sources",
    async resolveId(source, importer) {
      if (source === ENTRY_ID) return ENTRY_ID;
      if (source === "@hpke/hpke-js") this.error(HPKE_JS_FORBIDDEN);
      const m = HPKE_SPECIFIER.exec(source);
      if (m !== null) {
        return {
          id: hpkeEntryPath(m[1] + (m[2] ? "/" + m[2] : "")),
          moduleSideEffects: hpkeSideEffects(m[1]),
        };
      }
      const alias = NPM_ALIASES[source];
      if (alias !== undefined) {
        // Let node-resolve resolve the npm package (honoring its
        // package.json sideEffects) as if imported from the tool root.
        return await this.resolve(alias, join(TOOL_ROOT, "index.js"), {
          skipSelf: true,
        });
      }
      if (importer !== undefined && /^\.\.?\//.test(source)) {
        const pkg = hpkePackageOf(importer);
        if (pkg !== undefined) {
          return {
            id: resolve(dirname(importer), source),
            moduleSideEffects: hpkeSideEffects(pkg),
          };
        }
      }
      return null;
    },
    load(id) {
      return id === ENTRY_ID ? entrySource : null;
    },
    async transform(code, id) {
      if (!id.endsWith(".ts")) return null;
      const out = await esbuild.transform(code, {
        loader: "ts",
        format: "esm",
        target: TARGET,
        sourcefile: id,
      });
      return { code: out.code, map: null };
    },
  };
}

export const rollupBundler: Bundler = {
  id: "rollup",
  description: `rollup@${ROLLUP_VERSION} + @rollup/plugin-node-resolve@${
    version("@rollup/plugin-node-resolve")
  } + @rollup/plugin-terser@${version("@rollup/plugin-terser")} (terser@${
    version("terser")
  }), format=es, inlineDynamicImports`,
  async bundle(source: string): Promise<BundleOutput> {
    const build = await rollup({
      input: ENTRY_ID,
      external: [...EXTERNALS],
      plugins: [
        hpkeSources(source),
        nodeResolve({ rootDir: TOOL_ROOT }),
      ],
      onwarn(warning, warn) {
        if (warning.code && IGNORED_WARNINGS.has(warning.code)) return;
        warn(warning);
      },
    });
    try {
      const { output } = await build.generate({
        format: "es",
        // Measure the complete
        // application in one file, matching esbuild's non-splitting build.
        inlineDynamicImports: true,
        plugins: [terser({ format: { comments: false } })],
      });
      const chunk = output[0];
      return {
        code: new TextEncoder().encode(chunk.code),
        includedModules: Object.entries(chunk.modules)
          .filter(([, info]) => info.renderedLength > 0)
          .map(([id]) => id),
      };
    } finally {
      await build.close();
    }
  },
};
