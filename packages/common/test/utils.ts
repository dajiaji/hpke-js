declare const Deno: undefined;
const isDeno = () => typeof Deno !== "undefined";

export function testVectorPath(): string {
  if (isDeno()) {
    return "./test/vectors";
  }
  return "../../../test/vectors";
}

export function hexToBytes(v: string): Uint8Array {
  if (v.length === 0) {
    return new Uint8Array([]);
  }
  const res = v.match(/[\da-f]{2}/gi);
  if (res == null) {
    throw new Error("Not hex string.");
  }
  return new Uint8Array(res.map(function (h) {
    return parseInt(h, 16);
  }));
}

export function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function hexToDec(hexString: string): number {
  return parseInt(hexString, 16);
}

export function parseKAT(data: string) {
  const textByLine = data.trim().split("\n");
  const parsed: { [label: string]: Uint8Array[] } = {};

  for (let i = 0; i < textByLine.length; i++) {
    const [label, hexValue] = textByLine[i].split(" = ");
    if (label === "count") continue;
    const value = hexToBytes(hexValue);
    if (parsed[label]) {
      parsed[label].push(value);
    } else {
      parsed[label] = [value];
    }
  }

  return parsed;
}

/**
 * Following functions are imported from noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/test/utils.ts
 */

// Everything except undefined, string, Uint8Array
// deno-lint-ignore no-explicit-any
const TYPE_TEST_BASE: any[] = [
  null,
  [1, 2, 3],
  { a: 1, b: 2, c: 3 },
  NaN,
  0.1234,
  1.0000000000001,
  10e9999,
  new Uint32Array([1, 2, 3]),
  100n,
  new Set([1, 2, 3]),
  new Map([["aa", "bb"]]),
  new Uint8ClampedArray([1, 2, 3]),
  new Int16Array([1, 2, 3]),
  new Float32Array([1]),
  new BigInt64Array([1n, 2n, 3n]),
  new ArrayBuffer(100),
  new DataView(new ArrayBuffer(100)),
  { constructor: { name: "Uint8Array" }, length: "1e30" },
  () => {},
  async () => {},
  class Test {},
  Symbol.for("a"),
  new Proxy(new Uint8Array(), {
    get(t, p, r) {
      if (p === "isProxy") return true;
      return Reflect.get(t, p, r);
    },
  }),
];

export const SPACE = {
  str: " ",
  bytes: new Uint8Array([0x20]),
};

export const EMPTY = {
  str: "",
  bytes: new Uint8Array([]),
};

// deno-lint-ignore no-explicit-any
const TYPE_TEST_OPT: any[] = [
  "",
  new Uint8Array(),
  new (class Test {})(),
  class Test {},
  () => {},
  0,
  0.1234,
  NaN,
  null,
];

// deno-lint-ignore no-explicit-any
const TYPE_TEST_NOT_BOOL: any[] = [false, true];
// deno-lint-ignore no-explicit-any
const TYPE_TEST_NOT_BYTES: any[] = [
  "",
  "test",
  "1",
  new Uint8Array([]),
  new Uint8Array([1, 2, 3]),
];
// deno-lint-ignore no-explicit-any
const TYPE_TEST_NOT_HEX: any[] = [
  "0xbe",
  " 1 2 3 4 5",
  "010203040x",
  "abcdefgh",
  "1 2 3 4 5 ",
  "bee",
  new String("1234"),
];
const TYPE_TEST_NOT_INT = [-0.0, 0, 1];

export const TYPE_TEST = {
  int: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_BOOL, TYPE_TEST_NOT_BYTES),
  bytes: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BOOL),
  boolean: TYPE_TEST_BASE.concat(TYPE_TEST_NOT_INT, TYPE_TEST_NOT_BYTES),
  hex: TYPE_TEST_BASE.concat(
    TYPE_TEST_NOT_INT,
    TYPE_TEST_NOT_BOOL,
    TYPE_TEST_NOT_HEX,
  ),
  opts: TYPE_TEST_OPT,
  hash: TYPE_TEST_BASE.concat(
    TYPE_TEST_NOT_BOOL,
    TYPE_TEST_NOT_INT,
    TYPE_TEST_NOT_BYTES,
    TYPE_TEST_OPT,
  ),
};

export const repeat = (buf: Uint8Array, len: number) => {
  // too slow: Uint8Array.from({ length: len * buf.length }, (_, i) => buf[i % buf.length]);
  const out = new Uint8Array(len * buf.length);
  for (let i = 0; i < len; i++) out.set(buf, i * buf.length);
  return out;
};

export const truncate = (
  buf: Uint8Array,
  length: number,
) => (length ? buf.slice(0, length) : buf);
