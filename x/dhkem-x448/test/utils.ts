export const isBrowser = () => typeof window !== "undefined";

export const isCloudflareWorkers = () => typeof caches !== "undefined";

export function hexStringToBytes(v: string): Uint8Array {
  if (v.length === 0) {
    return new Uint8Array([]);
  }
  const res = v.match(/[\da-f]{2}/gi);
  if (res == null) {
    throw new Error("hexStringToBytes: not hex string");
  }
  return new Uint8Array(res.map(function (h) {
    return parseInt(h, 16);
  }));
}

export async function loadCrypto(): Promise<Crypto> {
  if (isBrowser() || isCloudflareWorkers()) {
    if (globalThis.crypto !== undefined) {
      return globalThis.crypto;
    }
    // jsdom
  }

  try {
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto);
  } catch (_e: unknown) {
    throw new Error("Web Cryptograph API not supported");
  }
}

export async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (isBrowser() || isCloudflareWorkers()) {
    if (globalThis.crypto !== undefined) {
      return globalThis.crypto.subtle;
    }
    // jsdom
  }

  try {
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto).subtle;
  } catch (_e: unknown) {
    throw new Error("Web Cryptograph API not supported");
  }
}
