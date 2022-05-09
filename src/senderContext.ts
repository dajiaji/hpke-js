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
        name: this._alg,
        iv: this.computeNonce(this._f),
        additionalData: aad,
      };
      ct = await this._crypto.encrypt(alg, this._f.key, data);
    } catch (e: unknown) {
      throw new errors.SealError(e);
    }
    this.incrementSeq(this._f);
    return ct;
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    if (this._r.baseNonce.length === 0) {
      throw new errors.SealError('Bidirectional encryption is not setup');
    }
    let pt: ArrayBuffer;
    try {
      const alg = {
        name: this._alg,
        iv: this.computeNonce(this._r),
        additionalData: aad,
      };
      pt = await this._crypto.decrypt(alg, this._r.key, data);
    } catch (e: unknown) {
      throw new errors.OpenError(e);
    }
    this.incrementSeq(this._r);
    return pt;
  }
}
