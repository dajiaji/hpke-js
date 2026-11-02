import { build, emptyDir } from "@deno/dnt";
import { copySync } from "@std/fs";
import { afterBuild, beforeBuild } from "../../utils/dntCommon.ts";

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.jsonc"));

await beforeBuild("hpke-js");
await emptyDir("../../npm/samples/hpke-js-ts-node");
await emptyDir("../../npm/samples/hpke-js-ts-webpack");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/packages/hpke-js",
  typeCheck: "both",
  test: !Deno.args.includes("--skip-test"),
  declaration: "inline",
  scriptModule: "umd",
  importMap: "../../npm/import_map.json",
  packageManager: "../../../utils/dntNpm.ts",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  testPattern: "test/**/*.test.ts",
  package: {
    name: "hpke-js",
    version: denoPkg.version,
    description:
      "A Hybrid Public Key Encryption (HPKE) module for various JavaScript runtimes",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    funding: {
      type: "github",
      url: "https://github.com/sponsors/dajiaji",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    module: "./esm/mod.js",
    main: "./script/mod.js",
    types: "./esm/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/mod.js",
        "require": "./script/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "public-key-encryption",
      "rfc9180",
      "e2ee",
      "kem",
      "kdf",
      "kyber",
      "aead",
      "post-quantum",
      "pqc",
      "security",
      "encryption",
    ],
    engines: {
      "node": ">=16.0.0",
    },
    devDependencies: {
      "@deno/shim-deno": "~0.18.0",
      "picocolors": "^1.0.0",
    },
    author: "Ajitomi Daisuke",
    bugs: {
      url: "https://github.com/dajiaji/hpke-js/issues",
    },
  },
});

afterBuild("hpke-js");

// Add the TypeScript samples to the npm workspace so that they share
// npm/package-lock.json.
const tsSamples: Record<string, string[]> = {
  "ts-node": ["app.ts", "package.json", "tsconfig.json"],
  "ts-webpack": [
    "app.ts",
    "index.html",
    "index.js",
    "package.json",
    "tsconfig.json",
    "webpack.config.js",
  ],
};
for (const [sample, files] of Object.entries(tsSamples)) {
  for (const file of files) {
    copySync(
      `samples/${sample}/${file}`,
      `../../npm/samples/hpke-js-${sample}/${file}`,
      { overwrite: true },
    );
  }
}
