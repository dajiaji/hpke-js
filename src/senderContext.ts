import type { AeadParams } from './interfaces/aeadParams';
import type { Encapsulator } from './interfaces/encapsulator';
import type { KdfContext } from './kdfContext';

import { EMPTY } from './consts';
import { EncryptionContext } from './encryptionContext';

import * as errors from './errors';

export class SenderContext extends EncryptionContext implements Encapsulator {

  public readonly enc: ArrayBuffer;

  public constructor(crypto: SubtleCrypto, kdf: KdfContext, params: AeadParams, enc: ArrayBuffer) {
    super(crypto, kdf, params);
    this.enc = enc;
    return;
  }

  public async seal(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    let ct: ArrayBuffer;
    try {
      const alg = {
        name: 'AES-GCM',
        iv: this.computeNonce(),
        additionalData: aad,
      };
      ct = await window.crypto.subtle.encrypt(alg, this.key, data);
    } catch (e: unknown) {
      throw new errors.OpenError(e);
    }
    this.incrementSeq();
    return ct;
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    throw new errors.NotSupportedError('Bidirectional encryption not supported');
  }
}
