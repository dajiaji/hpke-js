import { EMPTY } from './consts';
import { EncryptionContext } from './encryptionContext';

import * as errors from './errors';

export class RecipientContext extends EncryptionContext {

  public async seal(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    throw new errors.NotSupportedError('Bidirectional encryption not supported');
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    let pt: ArrayBuffer;
    try {
      const alg = {
        name: 'AES-GCM',
        iv: this.computeNonce(),
        additionalData: aad,
      };
      pt = await window.crypto.subtle.decrypt(alg, this.key, data);
    } catch (e: unknown) {
      throw new errors.OpenError(e);
    }
    this.incrementSeq();
    return pt;
  }
}
