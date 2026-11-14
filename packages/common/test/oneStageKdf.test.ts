import {
  assertEquals,
  assertNotEquals,
  assertRejects,
  assertThrows,
} from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { createHash } from "node:crypto";

import type { KdfId } from "../mod.ts";
import {
  buildLabeledDeriveIkm,
  HkdfSha256Native,
  InvalidParamError,
  isOneStageKdf,
  Keccak,
  lengthPrefixed,
  NotSupportedError,
  OneStageKdf,
} from "../mod.ts";

/** A minimal one-stage KDF (SHAKE128) built on the exported Keccak class. */
class TestShake128 extends OneStageKdf {
  public readonly id: KdfId = 0x0010;
  public readonly hashSize: number = 32;

  protected _derive(ikm: Uint8Array, len: number): Uint8Array {
    return new Keccak(168, 0x1f, len, true).update(ikm).digest();
  }
}

/** SHAKE128 by node:crypto as an independent reference. */
function refShake128(input: Uint8Array, len: number): Uint8Array {
  return Uint8Array.from(
    createHash("shake128", { outputLength: len }).update(input).digest(),
  );
}

const te = new TextEncoder();
// "HPKE" || I2OSP(0x0010, 2) || I2OSP(0x0010, 2) || I2OSP(0x0001, 2)
// deno-fmt-ignore
const SUITE_ID = new Uint8Array([72, 80, 75, 69, 0, 16, 0, 16, 0, 1]);
const INVALID_LENGTHS = [-1, 1.5, 65536, Number.NaN, Infinity];

describe("lengthPrefixed", () => {
  it("should prepend the length as a 2-byte big-endian integer", () => {
    assertEquals(lengthPrefixed(new Uint8Array(0)), new Uint8Array([0, 0]));
    assertEquals(
      lengthPrefixed(new Uint8Array([0xaa, 0xbb, 0xcc])),
      new Uint8Array([0, 3, 0xaa, 0xbb, 0xcc]),
    );

    const x = new Uint8Array(0x0102).fill(7);
    const ret = lengthPrefixed(x);
    assertEquals(ret.byteLength, 2 + 0x0102);
    assertEquals(ret.subarray(0, 2), new Uint8Array([0x01, 0x02]));
    assertEquals(ret.subarray(2), x);
  });

  it("should accept an input of 65,535 bytes", () => {
    const ret = lengthPrefixed(new Uint8Array(65535));
    assertEquals(ret.byteLength, 65537);
    assertEquals(ret.subarray(0, 2), new Uint8Array([0xff, 0xff]));
  });

  it("should throw InvalidParamError for an input longer than 65,535 bytes", () => {
    assertThrows(
      () => lengthPrefixed(new Uint8Array(65536)),
      InvalidParamError,
      "Too long input to be length-prefixed",
    );
  });
});

describe("buildLabeledDeriveIkm", () => {
  it("should build ikm || 'HPKE-v1' || suite_id || lengthPrefixed(label) || I2OSP(L, 2) || context", () => {
    const ikm = new Uint8Array([1, 2, 3]);
    const label = te.encode("secret");
    const context = new Uint8Array([9, 8, 7, 6]);

    assertEquals(
      buildLabeledDeriveIkm(SUITE_ID, ikm, label, context, 0x0123),
      new Uint8Array([
        ...ikm,
        ...te.encode("HPKE-v1"),
        ...SUITE_ID,
        ...[0, 6],
        ...label,
        ...[0x01, 0x23],
        ...context,
      ]),
    );
  });

  it("should accept empty inputs and the boundary output lengths", () => {
    const empty = new Uint8Array(0);
    assertEquals(
      buildLabeledDeriveIkm(empty, empty, empty, empty, 0),
      new Uint8Array([...te.encode("HPKE-v1"), 0, 0, 0, 0]),
    );
    assertEquals(
      buildLabeledDeriveIkm(empty, empty, empty, empty, 65535),
      new Uint8Array([...te.encode("HPKE-v1"), 0, 0, 0xff, 0xff]),
    );
  });

  it("should throw InvalidParamError for an invalid output length", () => {
    const empty = new Uint8Array(0);
    for (const len of INVALID_LENGTHS) {
      assertThrows(
        () => buildLabeledDeriveIkm(SUITE_ID, empty, empty, empty, len),
        InvalidParamError,
        "Invalid length of the output",
      );
    }
  });

  it("should throw InvalidParamError for a label longer than 65,535 bytes", () => {
    const empty = new Uint8Array(0);
    assertThrows(
      () =>
        buildLabeledDeriveIkm(
          SUITE_ID,
          empty,
          new Uint8Array(65536),
          empty,
          32,
        ),
      InvalidParamError,
    );
  });
});

describe("isOneStageKdf", () => {
  it("should return true for a one-stage KDF", () => {
    assertEquals(isOneStageKdf(new TestShake128()), true);
  });

  it("should return false for a two-stage KDF", () => {
    assertEquals(isOneStageKdf(new HkdfSha256Native()), false);
  });
});

describe("OneStageKdf", () => {
  describe("derive", () => {
    it("should return the output of the underlying XOF with the requested length", async () => {
      const kdf = new TestShake128();
      const ikm = te.encode("input keying material");
      // Around the rate of SHAKE128 (168 bytes) and at the limit.
      for (const len of [1, 32, 167, 168, 169, 337, 65535]) {
        const okm = await kdf.derive(ikm, len);
        assertEquals(okm.byteLength, len, `output length ${len}`);
        assertEquals(
          new Uint8Array(okm),
          refShake128(ikm, len),
          `output length ${len}`,
        );
      }
    });

    it("should return an empty buffer for zero output length", async () => {
      const kdf = new TestShake128();
      assertEquals((await kdf.derive(new Uint8Array(8), 0)).byteLength, 0);
    });

    it("should work without init()", async () => {
      const kdf = new TestShake128();
      assertEquals((await kdf.derive(new Uint8Array(8), 16)).byteLength, 16);
    });

    it("should accept an ArrayBuffer and views with an offset", async () => {
      const kdf = new TestShake128();
      const ikm = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const expected = refShake128(ikm, 32);

      const padded = new Uint8Array(12);
      padded.set(ikm, 2);
      const inputs: (ArrayBufferLike | ArrayBufferView)[] = [
        ikm.slice().buffer,
        padded.subarray(2, 10),
        new DataView(padded.buffer, 2, 8),
      ];
      for (const input of inputs) {
        assertEquals(new Uint8Array(await kdf.derive(input, 32)), expected);
      }
    });

    it("should reject an invalid output length with InvalidParamError", async () => {
      const kdf = new TestShake128();
      for (const len of INVALID_LENGTHS) {
        await assertRejects(
          () => kdf.derive(new Uint8Array(8), len),
          InvalidParamError,
          "Invalid length of the output",
        );
      }
    });
  });

  describe("labeledDerive", () => {
    const ikm = te.encode("input keying material");
    const label = te.encode("secret");
    const context = te.encode("context");

    it("should reject if init() has not been called", async () => {
      const kdf = new TestShake128();
      await assertRejects(
        () => kdf.labeledDerive(ikm, label, context, 32),
        Error,
        "Not initialized. Call init()",
      );
    });

    it("should derive from the labeled input bound to suite_id", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      for (const len of [0, 1, 32, 169, 65535]) {
        const okm = await kdf.labeledDerive(ikm, label, context, len);
        assertEquals(okm.byteLength, len, `output length ${len}`);
        if (len === 0) {
          continue;
        }
        assertEquals(
          new Uint8Array(okm),
          refShake128(
            buildLabeledDeriveIkm(SUITE_ID, ikm, label, context, len),
            len,
          ),
          `output length ${len}`,
        );
      }
    });

    it("should be equivalent to derive() with the labeled input", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      assertEquals(
        new Uint8Array(await kdf.labeledDerive(ikm, label, context, 48)),
        new Uint8Array(
          await kdf.derive(
            buildLabeledDeriveIkm(SUITE_ID, ikm, label, context, 48),
            48,
          ),
        ),
      );
    });

    it("should accept an ArrayBuffer and views with an offset as ikm", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      const expected = new Uint8Array(
        await kdf.labeledDerive(ikm, label, context, 32),
      );

      const padded = new Uint8Array(ikm.byteLength + 4);
      padded.set(ikm, 3);
      const inputs: (ArrayBufferLike | ArrayBufferView)[] = [
        ikm.slice().buffer,
        padded.subarray(3, 3 + ikm.byteLength),
      ];
      for (const input of inputs) {
        assertEquals(
          new Uint8Array(await kdf.labeledDerive(input, label, context, 32)),
          expected,
        );
      }
    });

    it("should derive different outputs for different inputs", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      const base = new Uint8Array(
        await kdf.labeledDerive(ikm, label, context, 32),
      );

      const others = [
        await kdf.labeledDerive(te.encode("other"), label, context, 32),
        await kdf.labeledDerive(ikm, te.encode("other"), context, 32),
        await kdf.labeledDerive(ikm, label, te.encode("other"), 32),
        // The output length is a part of the input.
        (await kdf.labeledDerive(ikm, label, context, 33)).slice(0, 32),
      ];
      const otherSuite = new TestShake128();
      otherSuite.init(new Uint8Array([...SUITE_ID.subarray(0, 9), 2]));
      others.push(await otherSuite.labeledDerive(ikm, label, context, 32));

      for (const other of others) {
        assertNotEquals(new Uint8Array(other), base);
      }
    });

    it("should reject an invalid output length with InvalidParamError", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      for (const len of INVALID_LENGTHS) {
        await assertRejects(
          () => kdf.labeledDerive(ikm, label, context, len),
          InvalidParamError,
          "Invalid length of the output",
        );
      }
    });

    it("should reject a label longer than 65,535 bytes with InvalidParamError", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      await assertRejects(
        () => kdf.labeledDerive(ikm, new Uint8Array(65536), context, 32),
        InvalidParamError,
      );
    });
  });

  describe("two-stage functions", () => {
    it("should not be supported", async () => {
      const kdf = new TestShake128();
      kdf.init(SUITE_ID);
      const b = new Uint8Array(32);
      const msg = "Not supported by one-stage KDFs";

      assertThrows(() => kdf.buildLabeledIkm(b, b), NotSupportedError, msg);
      assertThrows(
        () => kdf.buildLabeledInfo(b, b, 32),
        NotSupportedError,
        msg,
      );
      await assertRejects(() => kdf.extract(b, b), NotSupportedError, msg);
      await assertRejects(() => kdf.expand(b, b, 32), NotSupportedError, msg);
      await assertRejects(
        () => kdf.extractAndExpand(b, b, b, 32),
        NotSupportedError,
        msg,
      );
      await assertRejects(
        () => kdf.labeledExtract(b, b, b),
        NotSupportedError,
        msg,
      );
      await assertRejects(
        () => kdf.labeledExpand(b, b, b, 32),
        NotSupportedError,
        msg,
      );
    });
  });
});
