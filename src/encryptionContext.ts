import type { AeadInterface } from "./interfaces/aeadInterface.ts";
import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { KeyInfo } from "./interfaces/keyInfo.ts";
import type { KdfInterface } from "./interfaces/kdfInterface.ts";

import { ExporterContext } from "./exporterContext.ts";
import { i2Osp, xor } from "./utils/misc.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

export class EncryptionContext extends ExporterContext {
  // AEAD id.
  protected _aead: AeadInterface;
  // The length in bytes of a key for the algorithm.
  protected _nK: number;
  // The length in bytes of a nonce for the algorithm.
  protected _nN: number;
  // The length in bytes of an authentication tag for the algorithm.
  protected _nT: number;
  // Forward (sender to recipient) encryption key information.
  protected _f: KeyInfo;
  // Reverse (recipient to sender) encryption key information.
  protected _r: KeyInfo;

  constructor(api: SubtleCrypto, kdf: KdfInterface, params: AeadParams) {
    super(api, kdf, params.exporterSecret);

    if (
      params.key === undefined || params.baseNonce === undefined ||
      params.seq === undefined
    ) {
      throw new Error("Required parameters are missing");
    }
    this._aead = params.aead;
    this._nK = this._aead.keySize;
    this._nN = this._aead.nonceSize;
    this._nT = this._aead.tagSize;

    const key = this._aead.createEncryptionContext(params.key);
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
  }

  protected computeNonce(k: KeyInfo): ArrayBuffer {
    const seqBytes = i2Osp(k.seq, k.baseNonce.byteLength);
    return xor(k.baseNonce, seqBytes);
  }

  protected incrementSeq(k: KeyInfo) {
    // if (this.seq >= (1 << (8 * this.baseNonce.byteLength)) - 1) {
    if (k.seq > Number.MAX_SAFE_INTEGER) {
      throw new errors.MessageLimitReachedError("Message limit reached");
    }
    k.seq += 1;
    return;
  }

  public async setupBidirectional(
    keySeed: ArrayBuffer,
    nonceSeed: ArrayBuffer,
  ): Promise<void> {
    try {
      this._r.baseNonce = new Uint8Array(
        await this.export(nonceSeed, this._nN),
      );
      const key = await this.export(keySeed, this._nK);
      this._r.key = this._aead.createEncryptionContext(key);
      this._r.seq = 0;
    } catch (e: unknown) {
      this._r.baseNonce = consts.EMPTY;
      throw e;
    }
  }
}
