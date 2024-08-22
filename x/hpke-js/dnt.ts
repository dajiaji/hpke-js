import { build, emptyDir } from "@deno/dnt";

await emptyDir("./npm");
await emptyDir("./samples/node/node_modules");
await emptyDir("./samples/ts-node/node_modules");
await emptyDir("./samples/ts-webpack/node_modules");
await emptyDir("./test/runtimes/browsers/node_modules");
await emptyDir("./test/runtimes/bun/node_modules");
await emptyDir("./test/runtimes/cloudflare/node_modules");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: "both",
  test: true,
  declaration: "inline",
  scriptModule: "umd",
  importMap: "./import_map.json",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "hpke-js",
    version: Deno.args[0],
    description:
      "A Hybrid Public Key Encryption (HPKE) module for various JavaScript runtimes",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    module: "./esm/x/hpke-js/mod.js",
    main: "./script/x/hpke-js/mod.js",
    types: "./esm/x/hpke-js/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/x/hpke-js/mod.js",
        "require": "./script/x/hpke-js/mod.js",
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
    author: "Ajitomi Daisuke",
    bugs: {
      url: "https://github.com/dajiaji/hpke-js/issues",
    },
  },
});

// post build steps
Deno.copyFileSync("../../LICENSE", "npm/LICENSE");
Deno.copyFileSync("../../README.md", "npm/README.md");
