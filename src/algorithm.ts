import { NotSupportedError } from "./errors.ts";
import { isBrowser, isCloudflareWorkers } from "./utils/misc.ts";

async function loadSubtleCrypto(): Promise<SubtleCrypto> {
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
