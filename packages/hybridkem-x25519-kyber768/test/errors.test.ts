import { assertEquals } from "@std/assert";

import { describe, it } from "@std/testing/bdd";

import { KyberError } from "../src/kyber/errors.ts";

describe("KyberError", () => {
  describe("constructor with neigher string or Error", () => {
    it("should have valid name and message", () => {
      const err = new KyberError(undefined);

      // assert
      assertEquals(err.name, "KyberError");
      assertEquals(err.message, "");
    });
  });

  describe("constructor with string", () => {
    it("should have valid name and message", () => {
      const err = new KyberError("failed");

      // assert
      assertEquals(err.name, "KyberError");
      assertEquals(err.message, "failed");
    });
  });

  describe("constructor with another Error", () => {
    it("should have valid name and message", () => {
      const origin = new Error("failed");
      const err = new KyberError(origin);

      // assert
      assertEquals(err.name, "KyberError");
      assertEquals(err.message, "failed");
    });
  });
});
