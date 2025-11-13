import { EMPTY, OpenError } from "@hpke/common";

import { EncryptionContextImpl } from "./encryptionContext.ts";
import { Mutex } from "./mutex.ts";

export class RecipientContextImpl extends EncryptionContextImpl {
  #mutex?: Mutex;

  override async open(
    data: ArrayBuffer,
    aad: ArrayBuffer = EMPTY.buffer as ArrayBuffer,
  ): Promise<ArrayBuffer> {
    this.#mutex ??= new Mutex();
    const release = await this.#mutex.lock();
    let pt: ArrayBuffer;
    try {
      pt = await this._ctx.key.open(this.computeNonce(this._ctx), data, aad);
    } catch (e: unknown) {
      throw new OpenError(e);
    } finally {
      release();
    }
    this.incrementSeq(this._ctx);
    return pt;
  }
}
