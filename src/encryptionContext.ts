import type { AeadParams } from './interfaces/aeadParams';
import type { KeyInfo } from './interfaces/keyInfo';
import type { KdfContext } from './kdfContext';

import { ExporterContext } from './exporterContext';
import { i2Osp, xor } from './utils';

import * as consts from './consts';
import * as errors from './errors';

export class EncryptionContext extends ExporterContext {

  /// AEAD algorithm identifier.
  protected _alg: string;
  /// The length in bytes of a key for the algorithm.
  protected _nK: number;
  /// The length in bytes of a nonce for the algorithm.
  protected _nN: number;
  /// The length in bytes of an authentication tag for the algorithm.
  protected _nT: number;
  /// Forward key information.
  protected _f: KeyInfo;
  /// Reverse key information.
  protected _r: KeyInfo;

  public constructor(crypto: SubtleCrypto, kdf: KdfContext, params: AeadParams) {
    super(crypto, kdf, params.exporterSecret);

    if (params.key === undefined || params.baseNonce === undefined || params.seq === undefined) {
      throw new errors.ValidationError('Required parameters are missing');
    }
    this._alg = params.alg;
    this._nK = params.nK;
    this._nN = params.nN;
    this._nT = params.nT;
    this._f = {
      key: params.key,
      baseNonce: params.baseNonce,
      seq: params.seq,
    };
    this._r = {
      key: params.key,
      baseNonce: consts.EMPTY,
      seq: 0,
    };
    return;
  }

  protected computeNonce(k: KeyInfo): ArrayBuffer {
    const seqBytes = i2Osp(k.seq, k.baseNonce.byteLength);
    return xor(k.baseNonce, seqBytes);
  }

  protected incrementSeq(k: KeyInfo) {
    // if (this.seq >= (1 << (8 * this.baseNonce.byteLength)) - 1) {
    if (k.seq >= Number.MAX_SAFE_INTEGER) {
      throw new errors.MessageLimitReachedError('Message limit reached');
    }
    k.seq += 1;
    return;
  }

  public async setupBidirectional(keySeed: ArrayBuffer, nonceSeed: ArrayBuffer): Promise<void> {
    try {
      this._r.baseNonce = new Uint8Array(await this.export(nonceSeed, this._nN));
      const key = await this.export(keySeed, this._nK);
      this._r.key = await this._crypto.importKey('raw', key, { name: this._alg }, true, consts.AEAD_USAGES);
      this._r.seq = 0;
    } catch (e: unknown) {
      this._r.baseNonce = consts.EMPTY;
      throw e;
    }
  }
}
