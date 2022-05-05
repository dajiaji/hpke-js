import type { AeadParams } from './interfaces/aeadParams';
import type { KdfContext } from './kdfContext';

import { ExporterContext } from './exporterContext';
import * as errors from './errors';
import { i2Osp, xor } from './utils';

export class EncryptionContext extends ExporterContext {

  protected readonly key: CryptoKey;
  protected readonly baseNonce: Uint8Array;
  protected seq: number;

  public constructor(kdf: KdfContext, params: AeadParams) {
    super(kdf, params.exporterSecret);

    if (params.key === undefined || params.baseNonce === undefined || params.seq === undefined) {
      throw new errors.ValidationError('Required parameters are missing');
    }
    this.key = params.key;
    this.baseNonce = params.baseNonce;
    this.seq = params.seq;
    return;
  }

  protected computeNonce(): ArrayBuffer {
    const seqBytes = i2Osp(this.seq, this.baseNonce.byteLength);
    return xor(this.baseNonce, seqBytes);
  }

  protected incrementSeq() {
    // if (this.seq >= (1 << (8 * this.baseNonce.byteLength)) - 1) {
    if (this.seq >= Number.MAX_SAFE_INTEGER) {
      throw new errors.MessageLimitReachedError('Message limit reached');
    }
    this.seq += 1;
    return;
  }
}
