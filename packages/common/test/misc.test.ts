import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { i2Osp, xor } from "../src/utils/misc.ts";

describe("i2Osp", () => {
  describe("with valid params (5, 1)", () => {
    it("return correct result", () => {
      assertEquals(i2Osp(5, 1), new Uint8Array([5]));
    });
  });

  describe("with valid params (5, 2)", () => {
    it("return correct result", () => {
      assertEquals(i2Osp(5, 2), new Uint8Array([0, 5]));
    });
  });

  describe("with valid params (5, 3)", () => {
    it("return correct result", () => {
      assertEquals(i2Osp(5, 3), new Uint8Array([0, 0, 5]));
    });
  });

  describe("with invalid n", () => {
    it("should throw Error", () => {
      assertThrows(() => i2Osp(256, 1), Error, "i2Osp: too large integer");
    });
  });

  describe("with invalid w (0)", () => {
    it("should throw Error", () => {
      assertThrows(() => i2Osp(255, 0), Error, "i2Osp: too small size");
    });
  });

  describe("with invalid w (negative value)", () => {
    it("should throw Error", () => {
      assertThrows(() => i2Osp(255, -1), Error, "i2Osp: too small size");
    });
  });

  describe("with 32-bit boundary values", () => {
    it("should handle 2^31-1 correctly", () => {
      const result = i2Osp(2 ** 31 - 1, 12);
      assertEquals(
        result,
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 127, 255, 255, 255]),
      );
    });

    it("should handle 2^31 correctly", () => {
      const result = i2Osp(2 ** 31, 12);
      assertEquals(
        result,
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0]),
      );
    });

    it("should handle 2^32-1 correctly", () => {
      const result = i2Osp(2 ** 32 - 1, 12);
      assertEquals(
        result,
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255]),
      );
    });

    it("should handle 2^32 correctly", () => {
      const result = i2Osp(2 ** 32, 12);
      assertEquals(
        result,
        new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
      );
    });

    it("should handle 2^48-1 correctly", () => {
      const result = i2Osp(2 ** 48 - 1, 12);
      assertEquals(
        result,
        new Uint8Array([0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255]),
      );
    });

    it("should handle Number.MAX_SAFE_INTEGER correctly", () => {
      // Number.MAX_SAFE_INTEGER = 2^53 - 1 = 0x1FFFFFFFFFFFFF
      const result = i2Osp(Number.MAX_SAFE_INTEGER, 12);
      assertEquals(
        result,
        new Uint8Array([0, 0, 0, 0, 0, 31, 255, 255, 255, 255, 255, 255]),
      );
    });
  });
});

describe("xor", () => {
  describe("with valid params", () => {
    it("return correct result", () => {
      const a = new Uint8Array([0, 1, 1]);
      const b = new Uint8Array([1, 1, 0]);
      assertEquals(xor(a, b), new Uint8Array([1, 0, 1]));
    });
  });

  describe("with different length inputs", () => {
    it("should throw Error", () => {
      const a = new Uint8Array([0, 1, 1]);
      const b = new Uint8Array([1, 1]);
      assertThrows(() => xor(a, b), Error, "xor: different length inputs");
    });
  });
});
