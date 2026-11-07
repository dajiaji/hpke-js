import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { HkdfSha256 } from "../mod.ts";

describe("HkdfSha256 variable salt", () => {
  it("should match WebCrypto HKDF for short, empty and long salts", async () => {
    const kdf = new HkdfSha256();
    const ikm = new Uint8Array(22).fill(0x0b);
    const info = new Uint8Array([1, 2, 3]);
    for (const length of [0, 13, 256]) {
      const salt = new Uint8Array(length).fill(7);
      const prk = await kdf.extract(salt, ikm);
      assertEquals(
        new Uint8Array(await kdf.expand(prk, info, 42)),
        new Uint8Array(await kdf.extractAndExpand(salt, ikm, info, 42)),
        `salt length ${length}`,
      );
    }
  });
});
