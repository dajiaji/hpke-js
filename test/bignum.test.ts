import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.142.0/testing/asserts.ts";

import { describe, it } from "https://deno.land/std@0.142.0/testing/bdd.ts";

import { Bignum } from "../src/utils/bignum.ts";

describe("Bignum", () => {
  describe("set", () => {
    it("should set properly", () => {
      const v = new Uint8Array([1, 0, 0, 0]);
      const num = new Bignum(4);
      num.set(v);

      // assert
      assertEquals(num.val(), new Uint8Array([1, 0, 0, 0]));
    });

    it("should throw error with different size of array", () => {
      const a = new Uint8Array([1, 0]);
      const b = new Uint8Array([1, 0, 0, 0]);
      const c = new Uint8Array([]);
      const d = new Uint8Array([1]);

      const num = new Bignum(3);

      // assert
      assertThrows(() => num.set(a), Error, "Bignum.set: invalid argument");
      assertThrows(() => num.set(b), Error, "Bignum.set: invalid argument");
      assertThrows(() => num.set(c), Error, "Bignum.set: invalid argument");
      assertThrows(() => num.set(d), Error, "Bignum.set: invalid argument");
    });
  });

  describe("reset", () => {
    it("should reset properly", () => {
      const v = new Uint8Array([1, 0, 0, 0]);
      const num = new Bignum(4);
      num.set(v);
      num.reset();

      // assert
      assertEquals(num.val(), new Uint8Array([0, 0, 0, 0]));
    });
  });

  describe("isZero", () => {
    it("should return true properly", () => {
      const v = new Uint8Array([0, 0, 0, 0]);
      const num = new Bignum(4);
      num.set(v);

      // assert
      assertEquals(num.isZero(), true);
    });

    it("should return false properly", () => {
      const v = new Uint8Array([1, 0, 0, 0]);
      const num = new Bignum(4);
      num.set(v);

      // assert
      assertEquals(num.isZero(), false);
    });
  });

  describe("lessThan", () => {
    it("should return proper result", () => {
      const a = new Uint8Array([1, 0, 0]);
      const b = new Uint8Array([1, 1, 0]);
      const c = new Uint8Array([0, 1, 0]);
      const d = new Uint8Array([1, 0, 0]);

      const num = new Bignum(3);
      num.set(a);

      // assert
      assertEquals(num.lessThan(b), true);
      assertEquals(num.lessThan(c), false);
      assertEquals(num.lessThan(d), false);
    });
  });

  describe("lessThan", () => {
    it("should throw error with different size of array", () => {
      const a = new Uint8Array([1, 0]);
      const b = new Uint8Array([1, 0, 0, 0]);
      const c = new Uint8Array([]);
      const d = new Uint8Array([1]);

      const num = new Bignum(3);

      // assert
      assertThrows(
        () => num.lessThan(a),
        Error,
        "Bignum.lessThan: invalid argument",
      );
      assertThrows(
        () => num.lessThan(b),
        Error,
        "Bignum.lessThan: invalid argument",
      );
      assertThrows(
        () => num.lessThan(c),
        Error,
        "Bignum.lessThan: invalid argument",
      );
      assertThrows(
        () => num.lessThan(d),
        Error,
        "Bignum.lessThan: invalid argument",
      );
    });
  });
});
