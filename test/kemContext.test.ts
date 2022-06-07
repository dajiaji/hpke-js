import { assertEquals } from "https://deno.land/std@0.142.0/testing/asserts.ts";

import { describe, it } from "https://deno.land/std@0.142.0/testing/bdd.ts";

import { KemContext } from "../src/kemContext.ts";
import { Kem } from "../src/identifiers.ts";
import { loadSubtleCrypto } from "../src/webCrypto.ts";

describe("constructor", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();

      // assert
      assertEquals(
        typeof new KemContext(api, Kem.DhkemP256HkdfSha256),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemP384HkdfSha384),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemP521HkdfSha512),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemX25519HkdfSha256),
        "object",
      );
      assertEquals(
        typeof new KemContext(api, Kem.DhkemX448HkdfSha512),
        "object",
      );
    });
  });
});
