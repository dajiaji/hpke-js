import { isBrowser, isCloudflareWorkers } from "./utils/misc.ts";

import * as errors from "./errors.ts";

export class WebCrypto {
  protected _api: SubtleCrypto;
  constructor(api: SubtleCrypto) {
    this._api = api;
  }
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
    throw new errors.NotSupportedError("Web Cryptograph API not supported");
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
    throw new errors.NotSupportedError("Web Cryptograph API not supported");
  }
}
