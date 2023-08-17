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
    lib: ["es2022", "dom"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "@hpke/hybridkem-x25519-kyber768",
    version: Deno.args[0],
    description:
      "A Hybrid Public Key Encryption (HPKE) extension module for a hybrid qost-quantum KEM which is the parallel combination of DHKEM(X25519, HKDF-SHA256) and Kyber768 (EXPERIMENTAL)",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    module: "./esm/x/hybridkem-x25519-kyber768/mod.js",
    main: "./script/x/hybridkem-x25519-kyber768/mod.js",
    types: "./esm/x/hybridkem-x25519-kyber768/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/x/hybridkem-x25519-kyber768/mod.js",
        "require": "./script/x/hybridkem-x25519-kyber768/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "rfc9180",
      "kem",
      "kyber",
      "x25519",
      "post-quantum",
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
