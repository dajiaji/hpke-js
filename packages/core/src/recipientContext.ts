import { EMPTY, OpenError } from "@hpke/common";

import { EncryptionContextImpl } from "./encryptionContext.ts";

export class RecipientContextImpl extends EncryptionContextImpl {
  override async open(
    data: ArrayBuffer,
    aad: ArrayBuffer = EMPTY.buffer as ArrayBuffer,
  ): Promise<ArrayBuffer> {
    let pt: ArrayBuffer;
    try {
      pt = await this._ctx.key.open(this.computeNonce(this._ctx), data, aad);
    } catch (e: unknown) {
      throw new OpenError(e);
    }
    this.incrementSeq(this._ctx);
    return pt;
  }
}
