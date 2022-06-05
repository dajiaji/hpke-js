import { build, emptyDir } from "https://deno.land/x/dnt@0.25.1/mod.ts";

await emptyDir("./npm");
await emptyDir("./npm/esm");
await emptyDir("./npm/esm/test");
await emptyDir("./npm/esm/test/vectors");
await emptyDir("./npm/script");
await emptyDir("./npm/script/test");
await emptyDir("./npm/script/test/vectors");

Deno.copyFileSync(
  "test/vectors/ecdh_secp256r1_ecpoint_test.json",
  "npm/esm/test/vectors/ecdh_secp256r1_ecpoint_test.json",
);
Deno.copyFileSync(
  "test/vectors/ecdh_secp384r1_ecpoint_test.json",
  "npm/esm/test/vectors/ecdh_secp384r1_ecpoint_test.json",
);
Deno.copyFileSync(
  "test/vectors/ecdh_secp521r1_ecpoint_test.json",
  "npm/esm/test/vectors/ecdh_secp521r1_ecpoint_test.json",
);
Deno.copyFileSync(
  "test/vectors/x25519_test.json",
  "npm/esm/test/vectors/x25519_test.json",
);
Deno.copyFileSync(
  "test/vectors/x448_test.json",
  "npm/esm/test/vectors/x448_test.json",
);
Deno.copyFileSync(
  "test/vectors/test-vectors.json",
  "npm/esm/test/vectors/test-vectors.json",
);

Deno.copyFileSync(
  "test/vectors/ecdh_secp256r1_ecpoint_test.json",
  "npm/script/test/vectors/ecdh_secp256r1_ecpoint_test.json",
);
Deno.copyFileSync(
  "test/vectors/ecdh_secp384r1_ecpoint_test.json",
  "npm/script/test/vectors/ecdh_secp384r1_ecpoint_test.json",
);
Deno.copyFileSync(
  "test/vectors/ecdh_secp521r1_ecpoint_test.json",
  "npm/script/test/vectors/ecdh_secp521r1_ecpoint_test.json",
);
Deno.copyFileSync(
  "test/vectors/x25519_test.json",
  "npm/script/test/vectors/x25519_test.json",
);
Deno.copyFileSync(
  "test/vectors/x448_test.json",
  "npm/script/test/vectors/x448_test.json",
);
Deno.copyFileSync(
  "test/vectors/test-vectors.json",
  "npm/script/test/vectors/test-vectors.json",
);

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
    description: "A Hybrid Public Key Encryption (HPKE) library",
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
    scripts: {
      'typedoc': 'typedoc',
    },
    devDependencies: {
      'typedoc': '^0.22.15',
    },
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
Deno.copyFileSync("typedoc.json", "npm/typedoc.json");
await emptyDir("./npm/esm/test");
await emptyDir("./npm/script/test");
