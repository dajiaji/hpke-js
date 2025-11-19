import type { KdfInterface } from "@hpke/common";
import { EMPTY, SealError } from "@hpke/common";

import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { Encapsulator } from "./interfaces/encapsulator.ts";
import { EncryptionContextImpl } from "./encryptionContext.ts";
import { Mutex } from "./mutex.ts";

export class SenderContextImpl extends EncryptionContextImpl
  implements Encapsulator {
  public readonly enc: ArrayBuffer;
  #mutex?: Mutex;

  constructor(
    api: SubtleCrypto,
    kdf: KdfInterface,
    params: AeadParams,
    enc: ArrayBuffer,
  ) {
    super(api, kdf, params);
    this.enc = enc;
  }

  override async seal(
    data: ArrayBuffer,
    aad: ArrayBuffer = EMPTY.buffer as ArrayBuffer,
  ): Promise<ArrayBuffer> {
    this.#mutex ??= new Mutex();
    const release = await this.#mutex.lock();
    let ct: ArrayBuffer;
    try {
      ct = await this._ctx.key.seal(this.computeNonce(this._ctx), data, aad);
    } catch (e: unknown) {
      throw new SealError(e);
    } finally {
      release();
    }
    this.incrementSeq(this._ctx);
    return ct;
  }
}
