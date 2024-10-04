import { build, emptyDir } from "@deno/dnt";

await emptyDir("../../npm/packages/dhkem-secp256k1");
await emptyDir("test/runtimes/browsers/node_modules");
await emptyDir("test/runtimes/bun/node_modules");
await emptyDir("test/runtimes/cloudflare/node_modules");

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.json"));

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/packages/dhkem-secp256k1",
  typeCheck: "both",
  test: true,
  declaration: true,
  scriptModule: "umd",
  importMap: "../../import_map.json",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  testPattern: "test/**/*.test.ts",
  package: {
    name: denoPkg.name,
    version: denoPkg.version,
    description:
      "A Hybrid Public Key Encryption (HPKE) module extension for secp256k1 curve (EXPERIMENTAL)",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    module: "./esm/dhkem-secp256k1/mod.js",
    main: "./script/dhkem-secp256k1/mod.js",
    types: "./esm/dhkem-secp256k1/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/dhkem-secp256k1/mod.js",
        "require": "./script/dhkem-secp256k1/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "rfc9180",
      "kem",
      "hkdf",
      "dh",
      "secp256k1",
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
Deno.copyFileSync("LICENSE", "../../npm/packages/dhkem-secp256k1/LICENSE");
Deno.copyFileSync(
  "README.md",
  "../../npm/packages/dhkem-secp256k1/README.md",
);
