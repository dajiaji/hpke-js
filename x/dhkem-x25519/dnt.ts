import { build, emptyDir } from "@deno/dnt";

await emptyDir("../../npm/x/dhkem-x25519");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/x/dhkem-x25519",
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
    module: "./esm/x/dhkem-x25519/mod.js",
    main: "./script/x/dhkem-x25519/mod.js",
    types: "./esm/x/dhkem-x25519/mod.d.ts",
    sideEffects: false,
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
Deno.copyFileSync("LICENSE", "../../npm/x/dhkem-x25519/LICENSE");
Deno.copyFileSync("README.md", "../../npm/x/dhkem-x25519/README.md");
