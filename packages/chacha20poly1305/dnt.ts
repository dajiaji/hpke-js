import { build, emptyDir } from "@deno/dnt";

await emptyDir("../../npm-packages/x/chacha20poly1305");
await emptyDir("test/runtimes/browsers/node_modules");
await emptyDir("test/runtimes/bun/node_modules");
await emptyDir("test/runtimes/cloudflare/node_modules");

const denoPkg = JSON.parse(await Deno.readTextFile("./deno.json"));

await build({
  entryPoints: ["./mod.ts"],
  outDir: "../../npm-packages/x/chacha20poly1305",
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
      "A Hybrid Public Key Encryption (HPKE) module extension for ChaCha20/Poly1305",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage:
      "https://github.com/dajiaji/hpke-js/tree/main/x/chacha20poly1305#readme",
    license: "MIT",
    module: "./esm/chacha20poly1305/mod.js",
    main: "./script/chacha20poly1305/mod.js",
    types: "./esm/chacha20poly1305/mod.d.ts",
    sideEffects: false,
    exports: {
      ".": {
        "import": "./esm/chacha20poly1305/mod.js",
        "require": "./script/chacha20poly1305/mod.js",
      },
      "./package.json": "./package.json",
    },
    keywords: [
      "hpke",
      "rfc9180",
      "aead",
      "chacha20",
      "poly1305",
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
Deno.copyFileSync("LICENSE", "../../npm-packages/x/chacha20poly1305/LICENSE");
Deno.copyFileSync(
  "README.md",
  "../../npm-packages/x/chacha20poly1305/README.md",
);
