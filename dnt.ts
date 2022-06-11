import { build, emptyDir } from "https://deno.land/x/dnt@0.25.1/mod.ts";

await emptyDir("./npm");

await build({
  entryPoints: ["./mod.ts"],
  outDir: "./npm",
  typeCheck: true,
  test: true,
  declaration: true,
  scriptModule: "umd",
  compilerOptions: {
    lib: ["es2021", "dom"],
  },
  shims: {
    deno: "dev",
  },
  package: {
    name: "hpke-js",
    version: Deno.args[0],
    description: "A Hybrid Public Key Encryption (HPKE) module for web browsers, Node.js and Deno",
    repository: {
      type: "git",
      url: "git+https://github.com/dajiaji/hpke-js.git",
    },
    homepage: "https://github.com/dajiaji/hpke-js#readme",
    license: "MIT",
    main: "./script/mod.js",
    types: "./types/mod.d.ts",
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
      "hkdf",
      "dh",
      "security",
      "encryption",
      "odoh",
      "mls",
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
Deno.copyFileSync("LICENSE", "npm/LICENSE");
Deno.copyFileSync("README.md", "npm/README.md");
