declare const Deno: undefined;
declare const caches: undefined;

/**
 * Checks whether the execution env is browser or not.
 */
export const isBrowser = () => typeof window !== "undefined";

/**
 * Checks whether the execution env is Cloudflare Workers or not.
 */
export const isCloudflareWorkers = () => typeof caches !== "undefined";

/**
 * Checks whether the execution env is Deno or not.
 */
export const isDeno = () => typeof Deno !== "undefined";

/**
 * Checks whetehr the type of input is CryptoKeyPair or not.
 */
export const isCryptoKeyPair = (x: unknown): x is CryptoKeyPair =>
  typeof x === "object" &&
  x !== null &&
  typeof (x as CryptoKeyPair).privateKey === "object" &&
  typeof (x as CryptoKeyPair).publicKey === "object";

/**
 * Converts integer to octet string. I2OSP implementation.
 */
export function i2Osp(n: number, w: number): Uint8Array {
  if (w <= 0) {
    throw new Error("i2Osp: too small size");
  }
  if (n >= 256 ** w) {
    throw new Error("i2Osp: too large integer");
  }
  const ret = new Uint8Array(w);
  for (let i = 0; i < w && n; i++) {
    ret[w - (i + 1)] = n % 256;
    n = n >> 8;
  }
  return ret;
}

/**
 * Executes XOR of two byte strings.
 */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.byteLength !== b.byteLength) {
    throw new Error("xor: different length inputs");
  }
  const buf = new Uint8Array(a.byteLength);
  for (let i = 0; i < a.byteLength; i++) {
    buf[i] = a[i] ^ b[i];
  }
  return buf;
}

/**
 * Concatenates two Uint8Arrays.
 */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}

/**
 * Concatenates three Uint8Arrays.
 */
export function concat3(
  a: Uint8Array,
  b: Uint8Array,
  c: Uint8Array,
): Uint8Array {
  const ret = new Uint8Array(a.length + b.length + c.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  ret.set(c, a.length + b.length);
  return ret;
}

/**
 * Converts hex string to bytes.
 */
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

/**
 * Converts bytes to hex string.
 */
export function bytesToHex(v: Uint8Array) {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}
