declare const Deno: undefined;

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
 * Concatenates two Uint8Arrays.
 */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}

/**
 * Decodes Base64Url-encoded data.
 */
export function base64UrlToBytes(v: string): Uint8Array {
  const base64 = v.replace(/-/g, "+").replace(/_/g, "/");
  const byteString = atob(base64);
  const ret = new Uint8Array(byteString.length);
  for (let i = 0; i < byteString.length; i++) {
    ret[i] = byteString.charCodeAt(i);
  }
  return ret;
}
