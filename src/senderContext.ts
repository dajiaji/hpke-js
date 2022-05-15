import type { AeadParams } from './interfaces/aeadParams';
import type { Encapsulator } from './interfaces/encapsulator';
import type { KdfContext } from './kdfContext';

import { EMPTY } from './consts';
import { EncryptionContext } from './encryptionContext';

import * as errors from './errors';

export class SenderContext extends EncryptionContext implements Encapsulator {

  public readonly enc: ArrayBuffer;

  constructor(api: SubtleCrypto, kdf: KdfContext, params: AeadParams, enc: ArrayBuffer) {
    super(api, kdf, params);
    this.enc = enc;
    return;
  }

  public async seal(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    let ct: ArrayBuffer;
    try {
      ct = await this._f.key.encrypt(this.computeNonce(this._f), data, aad);
    } catch (e: unknown) {
      throw new errors.SealError(e);
    }
    this.incrementSeq(this._f);
    return ct;
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    if (this._r.baseNonce.length === 0) {
      throw new errors.OpenError('Bidirectional encryption is not setup');
    }
    let pt: ArrayBuffer;
    try {
      pt = await this._r.key.decrypt(this.computeNonce(this._r), data, aad);
    } catch (e: unknown) {
      throw new errors.OpenError(e);
    }
    this.incrementSeq(this._r);
    return pt;
  }
}
