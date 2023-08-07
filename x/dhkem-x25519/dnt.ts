import { build, emptyDir } from "dnt";

await emptyDir("./npm");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: "both",
  test: true,
  declaration: true,
  scriptModule: "umd",
  importMap: "./deno.json",
  compilerOptions: {
    lib: ["es2021", "dom"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "@hpke/dhkem-x25519",
    version: Deno.args[0],
    description:
      "A Hybrid Public Key Encryption (HPKE) module extension for X25519",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    main: "./script/x/dhkem-x25519/mod.js",
    types: "./script/x/dhkem-x25519/mod.d.ts",
    exports: {
      ".": {
        "import": "./esm/x/dhkem-x25519/mod.js",
        "require": "./script/x/dhkem-x25519/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "rfc9180",
      "kem",
      "hkdf",
      "dh",
      "x25519",
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
Deno.copyFileSync("README.md", "npm/README.md");
