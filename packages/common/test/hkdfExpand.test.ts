import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "../mod.ts";

for (const Kdf of [HkdfSha256Native, HkdfSha384Native, HkdfSha512Native]) {
  describe(`${Kdf.name} expand`, () => {
    it("should match WebCrypto HKDF across block boundaries and at the limit", async () => {
      const kdf = new Kdf();
      const salt = new Uint8Array(kdf.hashSize).fill(1);
      const ikm = new Uint8Array(32).fill(2);
      const info = new Uint8Array([0, 3, 4, 5, 0]).subarray(1, 4);
      const prk = await kdf.extract(salt, ikm);

      for (
        const len of [
          1,
          kdf.hashSize - 1,
          kdf.hashSize,
          kdf.hashSize + 1,
          2 * kdf.hashSize + 7,
          255 * kdf.hashSize,
        ]
      ) {
        assertEquals(
          new Uint8Array(await kdf.expand(prk, info, len)),
          new Uint8Array(await kdf.extractAndExpand(salt, ikm, info, len)),
          `output length ${len}`,
        );
      }
    });

    it("should return an empty buffer for zero output length", async () => {
      const kdf = new Kdf();
      const prk = new Uint8Array(kdf.hashSize).fill(1);
      assertEquals(
        (await kdf.expand(prk, new Uint8Array(), 0)).byteLength,
        0,
      );
    });

    it("should preserve fractional output length truncation", async () => {
      const kdf = new Kdf();
      const prk = new Uint8Array(kdf.hashSize).fill(1);
      const info = new Uint8Array([2, 3]);
      for (const len of [0, 1, kdf.hashSize, kdf.hashSize + 1]) {
        assertEquals(
          new Uint8Array(await kdf.expand(prk, info, len + 0.5)),
          new Uint8Array(await kdf.expand(prk, info, len)),
        );
      }
    });

    it("should reject output longer than 255 hash blocks", async () => {
      const kdf = new Kdf();
      await assertRejects(
        () =>
          kdf.expand(
            new Uint8Array(kdf.hashSize),
            new Uint8Array(),
            255 * kdf.hashSize + 1,
          ),
        Error,
        "Entropy limit reached",
      );
    });

    it("should reject oversized output before importing a key or allocating a buffer", async () => {
      const kdf = new Kdf();
      // An empty PRK would fail HMAC key import; MAX_SAFE_INTEGER and
      // Infinity would fail buffer allocation. Check the HKDF limit first.
      for (
        const len of [255 * kdf.hashSize + 1, Number.MAX_SAFE_INTEGER, Infinity]
      ) {
        for (const prk of [new Uint8Array(), new Uint8Array(kdf.hashSize)]) {
          await assertRejects(
            () => kdf.expand(prk, new Uint8Array(), len),
            Error,
            "Entropy limit reached",
          );
        }
      }
    });

    it("should encode the labeled info length as a 2-byte big-endian integer", () => {
      const kdf = new Kdf();
      kdf.init(new Uint8Array([1, 2, 3]));
      for (
        const [len, expected] of [
          [0, [0, 0]],
          [255, [0, 255]],
          [256, [1, 0]],
          [300, [1, 44]],
          [255 * kdf.hashSize, [
            (255 * kdf.hashSize) >> 8,
            (255 * kdf.hashSize) & 0xff,
          ]],
        ] as const
      ) {
        assertEquals(
          kdf.buildLabeledInfo(new Uint8Array([4]), new Uint8Array([5]), len)
            .subarray(0, 2),
          new Uint8Array(expected),
          `output length ${len}`,
        );
      }
    });

    it("should preserve RangeError for negative output length", async () => {
      const kdf = new Kdf();
      await assertRejects(
        () => kdf.expand(new Uint8Array(kdf.hashSize), new Uint8Array(), -1),
        RangeError,
      );
    });
  });
}
