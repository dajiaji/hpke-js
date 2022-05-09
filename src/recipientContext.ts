import { EMPTY } from './consts';
import { EncryptionContext } from './encryptionContext';

import * as errors from './errors';

export class RecipientContext extends EncryptionContext {

  public async seal(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    if (this._r.baseNonce.length === 0) {
      throw new errors.SealError("Bidirectional encryption is not setup");
    }
    let ct: ArrayBuffer;
    try {
      const alg = {
        name: this._alg,
        iv: this.computeNonce(this._r),
        additionalData: aad,
      };
      ct = await this._crypto.encrypt(alg, this._r.key, data);
    } catch (e: unknown) {
      throw new errors.SealError(e);
    }
    this.incrementSeq(this._r);
    return ct;
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    let pt: ArrayBuffer;
    try {
      const alg = {
        name: this._alg,
        iv: this.computeNonce(this._f),
        additionalData: aad,
      };
      pt = await this._crypto.decrypt(alg, this._f.key, data);
    } catch (e: unknown) {
      throw new errors.OpenError(e);
    }
    this.incrementSeq(this._f);
    return pt;
  }
}
