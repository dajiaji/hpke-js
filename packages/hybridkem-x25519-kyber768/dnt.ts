import { build, emptyDir } from "@deno/dnt";

await emptyDir("../../npm/packages/hybridkem-x25519-kyber768");
await emptyDir("test/runtimes/browsers/node_modules");
await emptyDir("test/runtimes/bun/node_modules");
await emptyDir("test/runtimes/cloudflare/node_modules");

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.json"));

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/packages/hybridkem-x25519-kyber768",
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
    name: denoPkg.name,
    version: denoPkg.version,
    description:
      "A Hybrid Public Key Encryption (HPKE) module extension for a hybrid post-quantum KEM, X25519Kyber768Draft00",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    module: "./esm/hybridkem-x25519-kyber768/mod.js",
    main: "./script/hybridkem-x25519-kyber768/mod.js",
    types: "./esm/hybridkem-x25519-kyber768/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/hybridkem-x25519-kyber768/mod.js",
        "require": "./script/hybridkem-x25519-kyber768/mod.js",
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
Deno.copyFileSync(
  "LICENSE",
  "../../npm/packages/hybridkem-x25519-kyber768/LICENSE",
);
Deno.copyFileSync(
  "README.md",
  "../../npm/packages/hybridkem-x25519-kyber768/README.md",
);
