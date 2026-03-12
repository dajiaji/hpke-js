import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { encode } from "../src/cbor/encoder.ts";
import { decode } from "../src/cbor/decoder.ts";
import type { CborValue } from "../src/cbor/types.ts";

describe("CBOR", () => {
  describe("round-trip", () => {
    it("should encode/decode unsigned integers", () => {
      for (const n of [0, 1, 23, 24, 255, 256, 65535, 65536, 1000000]) {
        assertEquals(decode(encode(n)), n);
      }
    });

    it("should encode/decode negative integers", () => {
      for (const n of [-1, -10, -24, -25, -256, -1000]) {
        assertEquals(decode(encode(n)), n);
      }
    });

    it("should encode/decode byte strings", () => {
      const empty = new Uint8Array(0);
      assertEquals(decode(encode(empty)), empty);

      const data = new Uint8Array([1, 2, 3, 4, 5]);
      assertEquals(decode(encode(data)), data);
    });

    it("should encode/decode text strings", () => {
      assertEquals(decode(encode("")), "");
      assertEquals(decode(encode("hello")), "hello");
      assertEquals(decode(encode("Encrypt0")), "Encrypt0");
    });

    it("should encode/decode null", () => {
      assertEquals(decode(encode(null)), null);
    });

    it("should encode/decode arrays", () => {
      const arr: CborValue[] = ["Encrypt0", new Uint8Array([1, 2]), 42];
      const decoded = decode(encode(arr)) as CborValue[];
      assertEquals(decoded[0], "Encrypt0");
      assertEquals(decoded[1], new Uint8Array([1, 2]));
      assertEquals(decoded[2], 42);
    });

    it("should encode/decode maps", () => {
      const map = new Map<CborValue, CborValue>();
      map.set(1, 35);
      map.set(-4, new Uint8Array([10, 20]));
      const decoded = decode(encode(map)) as Map<CborValue, CborValue>;
      assertEquals(decoded.get(1), 35);
      assertEquals(decoded.get(-4), new Uint8Array([10, 20]));
    });

    it("should encode/decode nested structures", () => {
      const inner = new Map<CborValue, CborValue>();
      inner.set(1, "alg");
      const arr: CborValue[] = ["test", inner, null];
      const decoded = decode(encode(arr)) as CborValue[];
      assertEquals(decoded[0], "test");
      assertEquals((decoded[1] as Map<CborValue, CborValue>).get(1), "alg");
      assertEquals(decoded[2], null);
    });
  });

  describe("deterministic map encoding", () => {
    it("should sort map keys by encoded byte order", () => {
      // Insertion order: 4, 1, -4
      const map1 = new Map<CborValue, CborValue>();
      map1.set(4, "kid");
      map1.set(1, "alg");
      map1.set(-4, "ek");

      // Insertion order: 1, -4, 4
      const map2 = new Map<CborValue, CborValue>();
      map2.set(1, "alg");
      map2.set(-4, "ek");
      map2.set(4, "kid");

      // Both should encode identically (deterministic)
      assertEquals(encode(map1), encode(map2));
    });
  });
});
