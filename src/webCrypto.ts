import { isBrowser } from './utils/misc';

import * as errors from './errors';

export class WebCrypto {
  protected _api: SubtleCrypto;
  constructor(api: SubtleCrypto) {
    this._api = api;
  }
}

export async function loadCrypto(): Promise<Crypto> {
  if (isBrowser()) {
    if (window.crypto !== undefined) {
      return window.crypto;
    }
    // jsdom
  }

  try {
    const { webcrypto } = await import('node:crypto');
    return (webcrypto as unknown as Crypto);
  } catch (e: unknown) {
    throw new errors.NotSupportedError('Web Cryptograph API not supported');
  }
}

export async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (isBrowser()) {
    if (window.crypto !== undefined) {
      return window.crypto.subtle;
    }
    // jsdom
  }

  try {
    const { webcrypto } = await import('node:crypto');
    return (webcrypto as unknown as Crypto).subtle;
  } catch (e: unknown) {
    throw new errors.NotSupportedError('Web Cryptograph API not supported');
  }
}
