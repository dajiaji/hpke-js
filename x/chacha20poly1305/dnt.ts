import { build, emptyDir } from "@deno/dnt";

await emptyDir("./npm");
await emptyDir("./test/runtimes/browsers/node_modules");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: "both",
  test: true,
  declaration: true,
  scriptModule: "umd",
  importMap: "./import_map.json",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "@hpke/chacha20poly1305",
    version: Deno.args[0],
    description:
      "A Hybrid Public Key Encryption (HPKE) module extension for ChaCha20/Poly1305",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage:
      "https://github.com/dajiaji/hpke-js/tree/main/x/chacha20poly1305#readme",
    license: "MIT",
    module: "./esm/x/chacha20poly1305/mod.js",
    main: "./script/x/chacha20poly1305/mod.js",
    types: "./esm/x/chacha20poly1305/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/x/chacha20poly1305/mod.js",
        "require": "./script/x/chacha20poly1305/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "rfc9180",
      "aead",
      "chacha20",
      "poly1305",
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
Deno.copyFileSync("LICENSE", "npm/LICENSE");
Deno.copyFileSync("README.md", "npm/README.md");
