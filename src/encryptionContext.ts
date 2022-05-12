import type { AeadKey } from './interfaces/aeadKey';
import type { AeadParams } from './interfaces/aeadParams';
import type { KeyInfo } from './interfaces/keyInfo';
import type { KdfContext } from './kdfContext';

import { AesGcmKey } from './aeads/AesGcmKey';
import { ExporterContext } from './exporterContext';
import { Aead } from './identifiers';
import { i2Osp, xor } from './utils';

import * as consts from './consts';
import * as errors from './errors';

export class EncryptionContext extends ExporterContext {

  /// AEAD id.
  protected _aead: Aead;
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

  public constructor(api: SubtleCrypto, kdf: KdfContext, params: AeadParams) {
    super(api, kdf, params.exporterSecret);

    if (params.key === undefined || params.baseNonce === undefined || params.seq === undefined) {
      throw new errors.ValidationError('Required parameters are missing');
    }
    this._aead = params.aead;
    this._nK = params.nK;
    this._nN = params.nN;
    this._nT = params.nT;

    const key = createAeadKey(this._aead, params.key, this._api);

    this._f = {
      key: key,
      baseNonce: params.baseNonce,
      seq: params.seq,
    };
    this._r = {
      key: key,
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
      this._r.key = await createAeadKey(this._aead, key, this._api);
      this._r.seq = 0;
    } catch (e: unknown) {
      this._r.baseNonce = consts.EMPTY;
      throw e;
    }
  }
}

function createAeadKey(aead: Aead, key: ArrayBuffer, api: SubtleCrypto): AeadKey {
  let ret: AeadKey;
  switch (aead) {
    case Aead.Aes128Gcm:
      return new AesGcmKey(key, api);
    case Aead.Aes256Gcm:
      return new AesGcmKey(key, api);
    default:
      throw new Error('invalid or unsupported AEAD id');
  }
}
