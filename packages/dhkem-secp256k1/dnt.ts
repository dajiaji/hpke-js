import { build } from "@deno/dnt";
import { afterBuild, beforeBuild } from "../../utils/dntCommon.ts";

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.jsonc"));
const outDir = "../../npm/packages/dhkem-secp256k1";

await beforeBuild("dhkem-secp256k1");

await build({
  entryPoints: ["./mod.ts"],
  outDir,
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
  postBuild() {
    // Copy test vectors next to the compiled test files so that
    // import.meta.url-based resolution works under Node.js too.
    try {
      Deno.mkdirSync(`${outDir}/esm/test/vectors`, { recursive: true });
      Deno.copyFileSync(
        "test/vectors/ecdh_secp256k1_test.json",
        `${outDir}/esm/test/vectors/ecdh_secp256k1_test.json`,
      );
      Deno.mkdirSync(`${outDir}/script/test/vectors`, { recursive: true });
      Deno.copyFileSync(
        "test/vectors/ecdh_secp256k1_test.json",
        `${outDir}/script/test/vectors/ecdh_secp256k1_test.json`,
      );
    } catch {
      // Test directories not created (--skip-test); skip.
    }
  },
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
      "hkdf",
      "dh",
      "secp256k1",
      "security",
      "encryption",
    ],
    engines: {
      "node": ">=16.0.0",
    },
    devDependencies: {
      "@deno/shim-deno": "~0.18.0",
      "picocolors": "^1.0.0",
    },
    author: "Ajitomi Daisuke",
    bugs: {
      url: "https://github.com/dajiaji/hpke-js/issues",
    },
  },
});

afterBuild("dhkem-secp256k1");
