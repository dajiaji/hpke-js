import { build } from "@deno/dnt";
import { copySync } from "@std/fs";
import { beforeBuild } from "../../utils/dntCommon.ts";

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.jsonc"));
const outDir = "../../npm/packages/cose";

await beforeBuild("cose");

await build({
  entryPoints: ["./mod.ts"],
  outDir,
  typeCheck: "both",
  test: !Deno.args.includes("--skip-test"),
  declaration: "inline",
  scriptModule: false,
  importMap: "../../npm/import_map.json",
  compilerOptions: {
    lib: ["ES2022", "DOM"],
  },
  shims: {
    deno: "dev",
  },
  testPattern: "test/**/*.test.ts",
  postBuild() {
    // Copy test fixture files needed by testvectors.test.ts (only when
    // tests are enabled — the directories do not exist with --skip-test).
    try {
      Deno.copyFileSync(
        "test/testvectors.txt",
        `${outDir}/esm/test/testvectors.txt`,
      );
    } catch {
      // Test directories not created (--skip-test); skip.
    }
    // Copy runtime test files.
    copySync(
      "test/runtimes/browsers",
      "../../npm/test/cose/runtimes/browsers",
      { overwrite: true },
    );
    copySync(
      "test/runtimes/cloudflare",
      "../../npm/test/cose/runtimes/cloudflare",
      { overwrite: true },
    );
    copySync(
      "test/runtimes/fastly",
      "../../npm/test/cose/runtimes/fastly",
      { overwrite: true },
    );
    // Copy package metadata.
    Deno.copyFileSync("LICENSE", `${outDir}/LICENSE`);
    Deno.copyFileSync("README.md", `${outDir}/README.md`);
  },
  package: {
    name: denoPkg.name,
    version: denoPkg.version,
    description:
      "COSE-HPKE (draft-ietf-cose-hpke) encryption for COSE_Encrypt0 and COSE_Encrypt",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage:
      "https://github.com/dajiaji/hpke-js/tree/main/packages/cose#readme",
    license: "MIT",
    main: "./esm/mod.js",
    types: "./esm/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/mod.js",
        "types": "./esm/mod.d.ts",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "cose",
      "rfc9180",
      "encryption",
      "security",
    ],
    engines: {
      "node": ">=20.0.0",
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
