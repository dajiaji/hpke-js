import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  hexToBytes,
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
  describe(`${Kdf.name} extract`, () => {
    it("should accept variable salt lengths with no argument or explicit undefined", async () => {
      for (const kdf of [new Kdf(), new Kdf(undefined)]) {
        for (const length of [1, 16, kdf.hashSize + 1]) {
          const salt = new Uint8Array(length).fill(0x5a);
          const ikm = new Uint8Array([1]);
          assertEquals(
            new Uint8Array(await kdf.extract(salt, ikm)),
            hmac(hash, salt, ikm),
          );
        }
      }
    });

    it("should match HMAC for variable salt lengths and sliced inputs", async () => {
      const kdf = new Kdf();
      const ikm = new Uint8Array([0, 1, 2, 3, 4, 0]).subarray(1, 5);
      for (const length of [0, 1, 16, 32, 48, 64, 65, 128, 129, 256]) {
        const backing = new Uint8Array(length + 4).fill(0xff);
        const salt = backing.subarray(2, length + 2);
        for (let i = 0; i < salt.length; i++) salt[i] = i & 0xff;
        const view = new DataView(
          salt.buffer,
          salt.byteOffset,
          salt.byteLength,
        );
        assertEquals(
          new Uint8Array(await kdf.extract(view, ikm)),
          hmac(hash, salt, ikm),
          `salt length ${length}`,
        );
      }
    });

    it("should normalize empty salts with no argument or explicit undefined", async () => {
      const ikm = new Uint8Array([1, 2, 3]);
      for (const kdf of [new Kdf(), new Kdf(undefined)]) {
        assertEquals(
          new Uint8Array(await kdf.extract(new Uint8Array(), ikm)),
          hmac(hash, new Uint8Array(kdf.hashSize), ikm),
        );
      }
    });

    it("should preserve legacy callback precedence and normalized arguments", async () => {
      const salt = new Uint8Array([0, 1, 2, 3, 0]).subarray(1, 4);
      const ikm = new Uint8Array([0, 4, 5, 0]).subarray(1, 3);
      const expected = new Uint8Array(7).fill(0xa5);
      let calls = 0;
      const kdf = new Kdf((actualSalt, actualIkm) => {
        calls++;
        assertEquals(actualSalt, salt);
        assertEquals(actualIkm, ikm);
        return expected;
      });
      assertEquals(new Uint8Array(await kdf.extract(salt, ikm)), expected);
      assertEquals(calls, 1);
      await kdf.extract(new Uint8Array(kdf.hashSize), ikm);
      await kdf.extract(new Uint8Array(), ikm);
      assertEquals(calls, 1);
    });

    it("should keep expand's PRK length validation", async () => {
      const kdf = new Kdf();
      for (const length of [kdf.hashSize - 1, kdf.hashSize + 1]) {
        await assertRejects(
          () => kdf.expand(new Uint8Array(length), new Uint8Array(), 16),
        );
      }
    });
  });
}

describe("HKDF variable salt RFC 5869", () => {
  it("should match test case 1 PRK and OKM", async () => {
    const kdf = new HkdfSha256Native();
    const prk = await kdf.extract(
      hexToBytes("000102030405060708090a0b0c"),
      new Uint8Array(22).fill(0x0b),
    );
    assertEquals(
      new Uint8Array(prk),
      hexToBytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
      ),
    );
    assertEquals(
      new Uint8Array(
        await kdf.expand(prk, hexToBytes("f0f1f2f3f4f5f6f7f8f9"), 42),
      ),
      hexToBytes(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
      ),
    );
  });
});
