import { isBrowser } from './utils';

import * as errors from './errors';

export class WebCrypto {
  protected _crypto: SubtleCrypto;
  public constructor(crypto: SubtleCrypto) {
    this._crypto = crypto;
  }
}

export async function loadSubtleCrypto(): Promise<SubtleCrypto> {
  if (isBrowser()) {
    if (window.crypto === undefined) {
      try {
        const crypto = await import('crypto');
        Object.defineProperty(global.self, 'crypto', { value: crypto.webcrypto });
      } catch (e: unknown) {
        throw new errors.NotSupportedError('Web Cryptograph API not supported');
      }
    }
    return window.crypto.subtle;
  }

  try {
    const { webcrypto } = await import('node:crypto');
    return (webcrypto as unknown as Crypto).subtle;
  } catch (e: unknown) {
    throw new errors.NotSupportedError('Web Cryptograph API not supported');
  }
}
