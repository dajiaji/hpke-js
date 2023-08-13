import { isBrowser, isCloudflareWorkers } from "./utils/misc.ts";

import * as errors from "./errors.ts";

export async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (isBrowser() || isCloudflareWorkers()) {
    if (globalThis.crypto !== undefined) {
      return globalThis.crypto.subtle;
    }
    // jsdom
  }

  try {
    // @ts-ignore: to ignore "crypto"
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto).subtle;
  } catch (_e: unknown) {
    throw new errors.NotSupportedError("Web Cryptograph API not supported");
  }
}
