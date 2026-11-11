import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
  hmac,
  sha256,
  sha384,
  sha512,
} from "../mod.ts";

const CASES = [
  [HkdfSha256Native, sha256],
  [HkdfSha384Native, sha384],
  [HkdfSha512Native, sha512],
] as const;

for (const [Kdf, hash] of CASES) {
  describe(`${Kdf.name} extract with the empty salt`, () => {
    it("should match HMAC with hashSize zero bytes on repeated and concurrent calls", async () => {
      const kdf = new Kdf();
      const zeros = new Uint8Array(kdf.hashSize);
      const ikms = Array.from(
        { length: 4 },
        (_, i) => new Uint8Array(i + 1).fill(i),
      );
      // Concurrent calls before and after the HMAC key for the empty salt is
      // cached.
      const concurrent = await Promise.all(
        ikms.map((ikm) => kdf.extract(new Uint8Array(), ikm)),
      );
      for (let i = 0; i < ikms.length; i++) {
        const expected = hmac(hash, zeros, ikms[i]);
        assertEquals(new Uint8Array(concurrent[i]), expected);
        assertEquals(
          new Uint8Array(await kdf.extract(new ArrayBuffer(0), ikms[i])),
          expected,
        );
      }
      // A non-empty salt does not use the cached key.
      const salt = new Uint8Array(kdf.hashSize).fill(1);
      assertEquals(
        new Uint8Array(await kdf.extract(salt, ikms[0])),
        hmac(hash, salt, ikms[0]),
      );
    });
  });
}
