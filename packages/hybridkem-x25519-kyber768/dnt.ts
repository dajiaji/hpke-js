import { build, emptyDir } from "@deno/dnt";
import { copySync } from "@std/fs";
import { removeNodeModules } from "../../utils/misc.ts";

// clean up dist
await emptyDir("../../npm/packages/hybridkem-x25519-kyber768");
await emptyDir("../../npm/samples/hybridkem-x25519-kyber768");
await emptyDir("../../npm/test/hybridkem-x25519-kyber768/runtimes/cloudflare");

// clean up node_modules
await removeNodeModules();

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.json"));

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm/packages/hybridkem-x25519-kyber768",
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
      "A Hybrid Public Key Encryption (HPKE) module extension for a hybrid post-quantum KEM, X25519Kyber768Draft00",
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

copySync(
  "samples/node",
  "../../npm/samples/hybridkem-x25519-kyber768",
  { overwrite: true },
);
copySync(
  "test/runtimes/cloudflare",
  "../../npm/test/hybridkem-x25519-kyber768/runtimes/cloudflare",
  { overwrite: true },
);

// post build steps
Deno.copyFileSync(
  "LICENSE",
  "../../npm/packages/hybridkem-x25519-kyber768/LICENSE",
);
Deno.copyFileSync(
  "README.md",
  "../../npm/packages/hybridkem-x25519-kyber768/README.md",
);
