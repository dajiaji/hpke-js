import { KemId } from "../identifiers.ts";

export function isNode(): boolean {
  // deno-lint-ignore no-explicit-any
  if ((globalThis as any).process === undefined) {
    return false;
  }
  // deno-lint-ignore no-explicit-any
  return (globalThis as any).process?.versions?.deno === undefined;
}

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
 * @param a Uint8Array
 * @param b Uint8Array
 * @returns Concatenated Uint8Array
 */
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}

/**
 * Decodes Base64Url-encoded data.
 * @param v Base64Url-encoded string
 * @returns Uint8Array
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

/**
 * Encodes Uint8Array to Base64Url.
 * @param v Uint8Array
 * @returns Base64Url-encoded string
 */
export function bytesToBase64Url(v: Uint8Array): string {
  return btoa(String.fromCharCode(...v))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=*$/g, "");
}

/**
 * Decodes hex string to Uint8Array.
 * @param v Hex string
 * @returns Uint8Array
 * @throws Error if the input is not a hex string.
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
 * Encodes Uint8Array to hex string.
 * @param v Uint8Array
 * @returns Hex string
 */
export function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Converts KemId to KeyAlgorithm.
 * @param kem KemId
 * @returns KeyAlgorithm
 */
export function kemToKeyGenAlgorithm(kem: KemId): KeyAlgorithm {
  switch (kem) {
    case KemId.DhkemP256HkdfSha256:
      return {
        name: "ECDH",
        namedCurve: "P-256",
      } as KeyAlgorithm;
    case KemId.DhkemP384HkdfSha384:
      return {
        name: "ECDH",
        namedCurve: "P-384",
      } as KeyAlgorithm;
    case KemId.DhkemP521HkdfSha512:
      return {
        name: "ECDH",
        namedCurve: "P-521",
      } as KeyAlgorithm;
    default:
      // case KemId.DhkemX25519HkdfSha256
      return {
        name: "X25519",
      };
  }
}

export async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (globalThis !== undefined && globalThis.crypto !== undefined) {
    // Browsers, Node.js >= v19, Cloudflare Workers, Bun, etc.
    return globalThis.crypto.subtle;
  }
  // Node.js <= v18
  try {
    // @ts-ignore: to ignore "crypto"
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto).subtle;
  } catch (_e: unknown) {
    throw new Error("Failed to load SubtleCrypto");
  }
}

export async function loadCrypto(): Promise<Crypto> {
  if (globalThis !== undefined && globalThis.crypto !== undefined) {
    // Browsers, Node.js >= v19, Cloudflare Workers, Bun, etc.
    return globalThis.crypto;
  }
  // Node.js <= v18
  try {
    // @ts-ignore: to ignore "crypto"
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto);
  } catch (_e: unknown) {
    throw new Error("Web Cryptograph API not supported");
  }
}

/**
 * XOR for Uint8Array.
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
