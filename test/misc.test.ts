import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.142.0/testing/asserts.ts";

import { describe, it } from "https://deno.land/std@0.142.0/testing/bdd.ts";

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
