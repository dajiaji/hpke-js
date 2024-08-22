import { KemId } from "../src/identifiers.ts";

export const isDeno = () => (globalThis as any).Deno?.version?.deno !== null;
export const isNode = () => (globalThis as any).process?.versions?.node != null;
export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}

export function testVectorPath(): string {
  if (isNode()) {
    return "../../../../test/vectors";
  }
  return "../../test/vectors";
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

export function bytesToBase64Url(v: Uint8Array): string {
  return btoa(String.fromCharCode(...v))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=*$/g, "");
}

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
