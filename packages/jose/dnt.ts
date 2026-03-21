import { build } from "@deno/dnt";
import { copySync } from "@std/fs";
import { beforeBuild } from "../../utils/dntCommon.ts";

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.jsonc"));
const outDir = "../../npm/packages/jose";

await beforeBuild("jose");

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
    // Copy runtime test files.
    copySync(
      "test/runtimes/browsers",
      "../../npm/test/jose/runtimes/browsers",
      { overwrite: true },
    );
    copySync(
      "test/runtimes/cloudflare",
      "../../npm/test/jose/runtimes/cloudflare",
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
      "JOSE-HPKE (draft-ietf-jose-hpke-encrypt) encryption for JWE Integrated and Key Encryption",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage:
      "https://github.com/dajiaji/hpke-js/tree/main/packages/jose#readme",
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
      "jose",
      "jwe",
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
