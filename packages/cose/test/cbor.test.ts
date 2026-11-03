import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { encode } from "../src/cbor/encoder.ts";
import { decode } from "../src/cbor/decoder.ts";
import type { CborValue } from "../src/cbor/types.ts";

function hex(s: string): Uint8Array {
  const bytes = new Uint8Array(s.length / 2);
  for (let i = 0; i < s.length; i += 2) {
    bytes[i / 2] = parseInt(s.substring(i, i + 2), 16);
  }
  return bytes;
}

// RFC 8949 Appendix A: data items within the scope of this codec.
const APPENDIX_A_SUPPORTED: [string, CborValue][] = [
  ["00", 0],
  ["01", 1],
  ["0a", 10],
  ["17", 23],
  ["1818", 24],
  ["1819", 25],
  ["1864", 100],
  ["1903e8", 1000],
  ["1a000f4240", 1000000],
  ["1b000000e8d4a51000", 1000000000000],
  ["20", -1],
  ["29", -10],
  ["3863", -100],
  ["3903e7", -1000],
  ["f6", null],
  ["40", new Uint8Array(0)],
  ["4401020304", new Uint8Array([1, 2, 3, 4])],
  ["60", ""],
  ["6161", "a"],
  ["6449455446", "IETF"],
  ["62225c", '"\\'],
  ["62c3bc", "\u00fc"],
  ["63e6b0b4", "\u6c34"],
  ["64f0908591", "\u{10151}"],
  ["80", []],
  ["83010203", [1, 2, 3]],
  ["8301820203820405", [1, [2, 3], [4, 5]]],
  [
    "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
    Array.from({ length: 25 }, (_, i) => i + 1),
  ],
  ["a0", new Map()],
  ["a201020304", new Map([[1, 2], [3, 4]])],
  [
    "a26161016162820203",
    new Map<CborValue, CborValue>([["a", 1], ["b", [2, 3]]]),
  ],
  ["826161a161626163", ["a", new Map([["b", "c"]])]],
  [
    "a56161614161626142616361436164614461656145",
    new Map([["a", "A"], ["b", "B"], ["c", "C"], ["d", "D"], ["e", "E"]]),
  ],
];

// RFC 8949 Appendix A: tagged data items. Tags are skipped on decoding.
const APPENDIX_A_TAGGED: [string, CborValue][] = [
  ["c074323031332d30332d32315432303a30343a30305a", "2013-03-21T20:04:00Z"],
  ["c11a514b67b0", 1363896240],
  ["c249010000000000000000", hex("010000000000000000")],
  ["c349010000000000000000", hex("010000000000000000")],
  ["d74401020304", new Uint8Array([1, 2, 3, 4])],
  ["d818456449455446", hex("6449455446")],
  [
    "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
    "http://www.example.com",
  ],
];

// RFC 8949 Appendix A: data items outside the scope of this codec, namely
// integers beyond the safe range, floats, other simple values and
// indefinite-length items.
const APPENDIX_A_UNSUPPORTED: string[] = [
  "1bffffffffffffffff",
  "3bffffffffffffffff",
  "f90000",
  "f98000",
  "f93c00",
  "fb3ff199999999999a",
  "f93e00",
  "f97bff",
  "fa47c35000",
  "fa7f7fffff",
  "fb7e37e43c8800759c",
  "f90001",
  "f90400",
  "f9c400",
  "fbc010666666666666",
  "f97c00",
  "f97e00",
  "f9fc00",
  "fa7f800000",
  "fa7fc00000",
  "faff800000",
  "fb7ff0000000000000",
  "fb7ff8000000000000",
  "fbfff0000000000000",
  "f4",
  "f5",
  "f7",
  "f0",
  "f8ff",
  "c1fb41d452d9ec200000",
  "5f42010243030405ff",
  "7f657374726561646d696e67ff",
  "9fff",
  "9f018202039f0405ffff",
  "9f01820203820405ff",
  "83018202039f0405ff",
  "83019f0203ff820405",
  "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
  "bf61610161629f0203ffff",
  "826161bf61626163ff",
  "bf6346756ef563416d7421ff",
];

// RFC 8949 Appendix F.1: examples of data items that are not well-formed.
const APPENDIX_F1_NOT_WELL_FORMED: Record<string, string[]> = {
  "end of input in a head": [
    "18",
    "19",
    "1a",
    "1b",
    "1901",
    "1a0102",
    "1b01020304050607",
    "38",
    "58",
    "78",
    "98",
    "9a01ff00",
    "b8",
    "d8",
    "f8",
    "f900",
    "fa0000",
    "fb000000",
  ],
  "definite-length strings with short data": [
    "41",
    "61",
    "5affffffff00",
    "5bffffffffffffffff010203",
    "7affffffff00",
    "7b7fffffffffffffff010203",
  ],
  "definite-length maps and arrays not closed with enough items": [
    "81",
    "818181818181818181",
    "8200",
    "a1",
    "a20102",
    "a100",
    "a2000000",
  ],
  "tag number not followed by tag content": ["c0"],
  "indefinite-length strings not closed by a break": ["5f4100", "7f6100"],
  "indefinite-length maps and arrays not closed by a break": [
    "9f",
    "9f0102",
    "bf",
    "bf01020102",
    "819f",
    "9f8000",
    "9f9f9f9f9fffffffff",
    "9f819f819f9fffffff",
  ],
  "reserved additional information values": [
    "1c",
    "1d",
    "1e",
    "3c",
    "3d",
    "3e",
    "5c",
    "5d",
    "5e",
    "7c",
    "7d",
    "7e",
    "9c",
    "9d",
    "9e",
    "bc",
    "bd",
    "be",
    "dc",
    "dd",
    "de",
    "fc",
    "fd",
    "fe",
  ],
  "reserved two-byte encodings of simple values": [
    "f800",
    "f801",
    "f818",
    "f81f",
  ],
  "indefinite-length string chunks not of the correct type": [
    "5f00ff",
    "5f21ff",
    "5f6100ff",
    "5f80ff",
    "5fa0ff",
    "5fc000ff",
    "5fe0ff",
    "7f4100ff",
  ],
  "indefinite-length string chunks not definite length": [
    "5f5f4100ffff",
    "7f7f6100ffff",
  ],
  "break on its own outside of an indefinite-length item": ["ff"],
  "break in a definite-length array or map or a tag": [
    "81ff",
    "8200ff",
    "a1ff",
    "a1ff00",
    "a100ff",
    "a20000ff",
    "9f81ff",
    "9f829f819f9fffffffff",
  ],
  "break in a value position of an indefinite-length map": [
    "bf00ff",
    "bf000000ff",
  ],
  "major type 0, 1, 6 with additional information 31": ["1f", "3f", "df"],
};

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

  describe("RFC 8949 Appendix A", () => {
    for (const [encoded, value] of APPENDIX_A_SUPPORTED) {
      it(`should decode and encode ${encoded}`, () => {
        assertEquals(decode(hex(encoded)), value);
        assertEquals(encode(value), hex(encoded));
      });
    }

    for (const [encoded, value] of APPENDIX_A_TAGGED) {
      it(`should skip the tag of ${encoded}`, () => {
        assertEquals(decode(hex(encoded)), value);
      });
    }

    for (const encoded of APPENDIX_A_UNSUPPORTED) {
      it(`should reject unsupported ${encoded}`, () => {
        assertThrows(() => decode(hex(encoded)), Error, "CBOR:");
      });
    }
  });

  describe("RFC 8949 Appendix F.1", () => {
    for (
      const [kind, examples] of Object.entries(APPENDIX_F1_NOT_WELL_FORMED)
    ) {
      it(`should reject ${kind}`, () => {
        for (const encoded of examples) {
          assertThrows(() => decode(hex(encoded)), Error);
        }
      });
    }
  });

  describe("strict decoding", () => {
    it("should reject duplicate integer map keys", () => {
      assertThrows(
        () => decode(hex("a201010102")),
        Error,
        "CBOR: duplicate map key",
      );
    });

    it("should reject duplicate keys with non-preferred encodings", () => {
      assertThrows(
        () => decode(hex("a200001800" + "00")),
        Error,
        "CBOR: duplicate map key",
      );
    });

    it("should reject duplicate text map keys", () => {
      assertThrows(
        () => decode(hex("a2616101616102")),
        Error,
        "CBOR: duplicate map key",
      );
    });

    it("should reject map keys other than integers and text", () => {
      for (const encoded of ["a14000", "a1f600", "a18000", "a1a000"]) {
        assertThrows(
          () => decode(hex(encoded)),
          Error,
          "CBOR: unsupported map key type",
        );
      }
    });

    it("should reject invalid UTF-8 in text strings", () => {
      assertThrows(
        () => decode(hex("62c328")),
        Error,
        "CBOR: invalid UTF-8 in text string",
      );
    });

    it("should keep a leading BOM in text strings", () => {
      assertEquals(decode(hex("63efbbbf")), "\ufeff");
    });

    it("should accept non-preferred integer encodings", () => {
      assertEquals(decode(hex("1817")), 23);
    });

    it("should limit the nesting depth", () => {
      const nested = (n: number) =>
        new Uint8Array([...new Array(n).fill(0x81), 0x00]);
      decode(nested(31));
      assertThrows(() => decode(nested(32)), Error, "CBOR: nesting too deep");
      assertThrows(
        () => decode(nested(200000)),
        Error,
        "CBOR: nesting too deep",
      );
    });

    it("should limit the nesting depth of tags", () => {
      const tags = new Uint8Array([...new Array(200000).fill(0xc0), 0x00]);
      assertThrows(() => decode(tags), Error, "CBOR: nesting too deep");
    });
  });
});
