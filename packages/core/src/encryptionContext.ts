import type { KdfInterface } from "@hpke/common";
import { i2Osp, MessageLimitReachedError, xor } from "@hpke/common";

import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { KeyInfo } from "./interfaces/keyInfo.ts";

import { ExporterContextImpl } from "./exporterContext.ts";

export class EncryptionContextImpl extends ExporterContextImpl {
  // The end-to-end encryption key information.
  protected _ctx: KeyInfo;

  constructor(kdf: KdfInterface, params: Required<AeadParams>) {
    super(kdf, params.exporterSecret);
    this._ctx = {
      key: params.aead.createEncryptionContext(params.key),
      baseNonce: params.baseNonce,
      seq: params.seq,
    };
  }

  protected computeNonce(k: KeyInfo): ArrayBuffer {
    const seqBytes = i2Osp(k.seq, k.baseNonce.byteLength);
    return xor(k.baseNonce, seqBytes).buffer as ArrayBuffer;
  }

  protected incrementSeq(k: KeyInfo) {
    // if (this.seq >= (1 << (8 * this.baseNonce.byteLength)) - 1) {
    if (k.seq > Number.MAX_SAFE_INTEGER) {
      throw new MessageLimitReachedError("Message limit reached");
    }
    k.seq += 1;
    return;
  }
}
