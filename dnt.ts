import { build, emptyDir } from "dnt";

await emptyDir("./npm");
await emptyDir("./core/npm");
await emptyDir("./x/chacha20poly1305/npm");
await emptyDir("./x/dhkem-secp256k1/npm");
await emptyDir("./x/dhkem-x25519/npm");
await emptyDir("./x/dhkem-x448/npm");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: "both",
  test: true,
  declaration: true,
  scriptModule: "umd",
  importMap: "./deno.json",
  compilerOptions: {
    lib: ["es2022", "dom"],
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
    main: "./script/mod.js",
    types: "./script/mod.d.ts",
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
      "hkdf",
      "dh",
      "security",
      "encryption",
      "odoh",
      "mls",
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
