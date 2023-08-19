import { NotSupportedError } from "./errors.ts";

async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (globalThis !== undefined && globalThis.crypto !== undefined) {
    // Browsers, Node.js >= v19, Cloudflare Workers, Bun, etc.
    return globalThis.crypto.subtle;
  }
  // Node.js <= v18
  try {
    // @ts-ignore: to ignore "crypto"
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto).subtle;
  } catch (e: unknown) {
    throw new NotSupportedError(e);
  }
}

export class NativeAlgorithm {
  protected _api: SubtleCrypto | undefined = undefined;

  constructor() {}

  protected async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadSubtleCrypto();
  }
}
