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
      ct = await this._r.key.encrypt(this.computeNonce(this._r), data, aad);
    } catch (e: unknown) {
      throw new errors.SealError(e);
    }
    this.incrementSeq(this._r);
    return ct;
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    let pt: ArrayBuffer;
    try {
      pt = await this._f.key.decrypt(this.computeNonce(this._f), data, aad);
    } catch (e: unknown) {
      throw new errors.OpenError(e);
    }
    this.incrementSeq(this._f);
    return pt;
  }
}
