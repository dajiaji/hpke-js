/** Verify emitted dependencies for the OHTTP factories with both bundlers. */
import assert from "node:assert/strict";
import { esbuildBundler } from "./bundlers/esbuild.ts";
import { rollupBundler } from "./bundlers/rollup.ts";

for (const bundler of [esbuildBundler, rollupBundler]) {
  for (const encoding of ["standard", "chunked"]) {
    const factory = encoding === "standard"
      ? "createStandardEncoding"
      : "createChunkedEncoding";
    const { modules, code, includedModules } = await bundler.bundle(`
      import { createOhttpClient, ${factory} } from "@hpke/ohttp";
      import {
        DhkemX25519HkdfSha256, HkdfSha256, Aes128Gcm,
      } from "@hpke/core";
      export const client = (keyConfig) => createOhttpClient({
        keyConfig,
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
        encoding: ${factory}(),
      });
    `);
    const names = includedModules ?? Object.keys(modules!);
    assert(
      !names.some((n) => /ohttp\/src\/(http|bhttp|server)\.ts$/.test(n)),
      "Low-level clients must exclude HTTP and gateway implementations",
    );
    if (encoding === "standard") {
      assert(
        !names.some((n) => /ohttp\/src\/chunked\.ts$/.test(n)),
        "Standard clients must exclude chunked encoding",
      );
    } else {
      assert(
        !names.some((n) => /ohttp\/src\/(encapsulation|standard)\.ts$/.test(n)),
        "Chunked clients must exclude standard encoding",
      );
    }
    assert(
      !names.some((n) => /dhkemP(256|384|521)/i.test(n)),
      "X25519 clients must exclude unused elliptic-curve primitives",
    );
    console.log(`${bundler.id} / ${encoding}: PASS (${code.length} bytes)`);
  }
}
