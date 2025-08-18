import { build } from "@deno/dnt";
import { afterBuild, beforeBuild } from "../../utils/dntCommon.ts";

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.jsonc"));

await beforeBuild("hpke-js");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/packages/hpke-js",
  typeCheck: "both",
  test: !Deno.args.includes("--skip-test"),
  declaration: "inline",
  scriptModule: "umd",
  importMap: "../../npm/import_map.json",
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
    author: "Ajitomi Daisuke",
    bugs: {
      url: "https://github.com/dajiaji/hpke-js/issues",
    },
  },
});

afterBuild("hpke-js");
