// deno-lint-ignore-file no-explicit-any
/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/utils.ts
 */

/**
 * Hex, bytes and number utilities.
 * @module
 */

import { loadCrypto } from "@hpke/common";

const _0n = /* @__PURE__ */ BigInt(0);

export interface Hash<T> {
  blockLen: number; // Bytes per block
  outputLen: number; // Bytes in output
  update(buf: Uint8Array): this;
  digestInto(buf: Uint8Array): void;
  digest(): Uint8Array;
  destroy(): void;
  _cloneInto(to?: T): T;
  clone(): T;
}

export type HashInfo = {
  oid?: Uint8Array; // DER encoded OID in bytes
};

/** Hash function */
export type CHash<T extends Hash<T> = Hash<any>, Opts = undefined> =
  & {
    outputLen: number;
    blockLen: number;
  }
  & HashInfo
  & (Opts extends undefined ? {
      (msg: Uint8Array): Uint8Array;
      create(): T;
    }
    : {
      (msg: Uint8Array, opts?: Opts): Uint8Array;
      create(opts?: Opts): T;
    });

/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
export function isBytes(a: unknown): a is Uint8Array {
  return a instanceof Uint8Array ||
    (ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array");
}

/** Asserts something is Uint8Array. */
export function abytes(
  value: Uint8Array,
  length?: number,
  title: string = "",
): Uint8Array {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== undefined;
  if (!bytes || (needsLen && len !== length)) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
  }
  return value;
}

/** Asserts something is hash */
export function ahash(h: CHash): void {
  if (typeof h !== "function" || typeof h.create !== "function") {
    throw new Error("Hash must wrapped by utils.createHasher");
  }
  anumber(h.outputLen);
  anumber(h.blockLen);
}

/** Asserts a hash instance has not been destroyed / finished */
export function aexists(instance: any, checkFinished = true): void {
  if (instance.destroyed) throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished) {
    throw new Error("Hash#digest() has already been called");
  }
}

/** Asserts output is properly-sized byte array */
export function aoutput(out: any, instance: any): void {
  abytes(out, undefined, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error('"digestInto() output" expected to be of length >=' + min);
  }
}

/** Asserts something is positive integer. */
export function anumber(n: number): void {
  if (!Number.isSafeInteger(n) || n < 0) {
    throw new Error("positive integer expected, got " + n);
  }
}

// Used in weierstrass, der
function abignumer(n: number | bigint) {
  if (typeof n === "bigint") {
    if (!isPosBig(n)) throw new Error("positive bigint expected, got " + n);
  } else anumber(n);
  return n;
}

/** Generic type encompassing 8/16/32-byte arrays - but not 64-byte. */
// prettier-ignore
export type TypedArray =
  | Int8Array
  | Uint8ClampedArray
  | Uint8Array
  | Uint16Array
  | Int16Array
  | Uint32Array
  | Int32Array;

/** Zeroize a byte array. Warning: JS provides no guarantees. */
export function clean(...arrays: TypedArray[]): void {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}

/** Create DataView of an array for easy byte-level manipulation. */
export function createView(arr: TypedArray): DataView {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}

/** The rotate right (circular right shift) operation for uint32 */
export function rotr(word: number, shift: number): number {
  return (word << (32 - shift)) | (word >>> shift);
}

// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin: boolean = /* @__PURE__ */ (() =>
  // @ts-ignore: to use toHex
  typeof Uint8Array.from([]).toHex === "function" &&
  // @ts-ignore: to use fromHex
  typeof Uint8Array.fromHex === "function")();

// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from(
  { length: 256 },
  (_, i) => i.toString(16).padStart(2, "0"),
);

/**
 * Convert byte array to hex string. Uses built-in function, when available.
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
export function bytesToHex(bytes: Uint8Array): string {
  abytes(bytes);
  // @ts-ignore: to use toHex
  if (hasHexBuiltin) return bytes.toHex();
  // pre-caching improves the speed 6x
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}

// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 } as const;
function asciiToBase16(ch: number): number | undefined {
  if (ch >= asciis._0 && ch <= asciis._9) return ch - asciis._0; // '2' => 50-48
  if (ch >= asciis.A && ch <= asciis.F) return ch - (asciis.A - 10); // 'B' => 66-(65-10)
  if (ch >= asciis.a && ch <= asciis.f) return ch - (asciis.a - 10); // 'b' => 98-(97-10)
  return;
}

/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string") {
    throw new Error("hex string expected, got " + typeof hex);
  }
  // @ts-ignore: to use fromHex
  if (hasHexBuiltin) return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2) {
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  }
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error(
        'hex string expected, got non-hex character "' + char + '" at index ' +
          hi,
      );
    }
    array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
  }
  return array;
}

export function numberToHexUnpadded(num: number | bigint): string {
  const hex = abignumer(num).toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}

export function hexToNumber(hex: string): bigint {
  if (typeof hex !== "string") {
    throw new Error("hex string expected, got " + typeof hex);
  }
  return hex === "" ? _0n : BigInt("0x" + hex); // Big Endian
}

// BE: Big Endian, LE: Little Endian
export function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}
export function bytesToNumberLE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
}

export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  anumber(len);
  n = abignumer(n);
  const res = hexToBytes(n.toString(16).padStart(len * 2, "0"));
  if (res.length !== len) throw new Error("number too large");
  return res;
}
export function numberToBytesLE(n: number | bigint, len: number): Uint8Array {
  return numberToBytesBE(n, len).reverse();
}

/**
 * Copies Uint8Array. We can't use u8a.slice(), because u8a can be Buffer,
 * and Buffer#slice creates mutable copy. Never use Buffers!
 */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return Uint8Array.from(bytes);
}

/**
 * Decodes 7-bit ASCII string to Uint8Array, throws on non-ascii symbols
 * Should be safe to use for things expected to be ASCII.
 * Returns exact same result as utf8ToBytes for ASCII or throws.
 */
export function asciiToBytes(ascii: string): Uint8Array {
  return Uint8Array.from(ascii, (c, i) => {
    const charCode = c.charCodeAt(0);
    if (c.length !== 1 || charCode > 127) {
      throw new Error(
        `string contains non-ASCII character "${
          ascii[i]
        }" with code ${charCode} at position ${i}`,
      );
    }
    return charCode;
  });
}

// Is positive bigint
const isPosBig = (n: bigint) => typeof n === "bigint" && _0n <= n;

export function inRange(n: bigint, min: bigint, max: bigint): boolean {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}

/**
 * Asserts min <= n < max. NOTE: It's < max and not <= max.
 * @example
 * aInRange('x', x, 1n, 256n); // would assume x is in (1n..255n)
 */
export function aInRange(
  title: string,
  n: bigint,
  min: bigint,
  max: bigint,
): void {
  // Why min <= n < max and not a (min < n < max) OR b (min <= n <= max)?
  // consider P=256n, min=0n, max=P
  // - a for min=0 would require -1:          `inRange('x', x, -1n, P)`
  // - b would commonly require subtraction:  `inRange('x', x, 0n, P - 1n)`
  // - our way is the cleanest:               `inRange('x', x, 0n, P)
  if (!inRange(n, min, max)) {
    throw new Error(
      "expected valid " + title + ": " + min + " <= n < " + max + ", got " + n,
    );
  }
}

export function validateObject(
  object: Record<string, any>,
  fields: Record<string, string> = {},
  optFields: Record<string, string> = {},
): void {
  if (!object || typeof object !== "object") {
    throw new Error("expected valid options object");
  }
  type Item = keyof typeof object;
  function checkField(fieldName: Item, expectedType: string, isOpt: boolean) {
    const val = object[fieldName];
    if (isOpt && val === undefined) return;
    const current = typeof val;
    if (current !== expectedType || val === null) {
      throw new Error(
        `param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`,
      );
    }
  }
  const iter = (f: typeof fields, isOpt: boolean) =>
    Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
  iter(fields, false);
  iter(optFields, true);
}

export interface CryptoKeys {
  lengths: { seed?: number; public?: number; secret?: number };
  keygen: (
    seed?: Uint8Array,
  ) => { secretKey: Uint8Array; publicKey: Uint8Array };
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
}

/** Generic interface for signatures. Has keygen, sign and verify. */
export interface Signer extends CryptoKeys {
  // Interfaces are fun. We cannot just add new fields without copying old ones.
  lengths: {
    seed?: number;
    public?: number;
    secret?: number;
    signRand?: number;
    signature?: number;
  };
  sign: (msg: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean;
}

export type HasherCons<T, Opts = undefined> = Opts extends undefined ? () => T
  : (opts?: Opts) => T;

export function createHasher<T extends Hash<T>, Opts = undefined>(
  hashCons: HasherCons<T, Opts>,
  info: HashInfo = {},
): CHash<T, Opts> {
  const hashC: any = (msg: Uint8Array, opts?: Opts) =>
    hashCons(opts).update(msg).digest();
  const tmp = hashCons(undefined);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = (opts?: Opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}

// /** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
// export function randomBytes(bytesLength = 32): Uint8Array {
//   const cr = typeof globalThis != null && (globalThis as any).crypto;
//   if (!cr || typeof cr.getRandomValues !== "function") {
//     throw new Error("crypto.getRandomValues must be defined");
//   }
//   return cr.getRandomValues(new Uint8Array(bytesLength));
// }

/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
export async function randomBytesAsync(bytesLength = 32): Promise<Uint8Array> {
  const api = await loadCrypto();
  const rnd = new Uint8Array(bytesLength);
  api.getRandomValues(rnd);
  return rnd;
}

// 06 09 60 86 48 01 65 03 04 02
export const oidNist = (suffix: number): { oid: Uint8Array } => ({
  oid: Uint8Array.from([
    0x06,
    0x09,
    0x60,
    0x86,
    0x48,
    0x01,
    0x65,
    0x03,
    0x04,
    0x02,
    suffix,
  ]),
});
