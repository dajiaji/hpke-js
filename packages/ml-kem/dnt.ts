import { build, emptyDir } from "@deno/dnt";
import { copySync } from "@std/fs";

await emptyDir("../../npm/packages/ml-kem");
await emptyDir("../../npm/samples/ml-kem");
await emptyDir("../../npm/test/ml-kem/runtimes/cloudflare");

await emptyDir("test/runtimes/browsers/node_modules");
await emptyDir("test/runtimes/bun/node_modules");

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.json"));

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/packages/ml-kem",
  typeCheck: "both",
  test: true,
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
    name: denoPkg.name,
    version: denoPkg.version,
    description:
      "A Hybrid Public Key Encryption (HPKE) module extension for ML-KEM.",
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
      "ml-kem",
      "kyber",
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

copySync(
  "samples/node",
  "../../npm/samples/ml-kem",
  { overwrite: true },
);
copySync(
  "test/runtimes/cloudflare",
  "../../npm/test/ml-kem/runtimes/cloudflare",
  { overwrite: true },
);

// post build steps
Deno.copyFileSync("LICENSE", "../../npm/packages/ml-kem/LICENSE");
Deno.copyFileSync("README.md", "../../npm/packages/ml-kem/README.md");
