import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { Encapsulator } from "./interfaces/encapsulator.ts";
import type { KdfInterface } from "./interfaces/kdfInterface.ts";

import { EMPTY } from "./consts.ts";
import { EncryptionContext } from "./encryptionContext.ts";

import * as errors from "./errors.ts";

export class SenderContext extends EncryptionContext implements Encapsulator {
  public readonly enc: ArrayBuffer;

  constructor(
    api: SubtleCrypto,
    kdf: KdfInterface,
    params: AeadParams,
    enc: ArrayBuffer,
  ) {
    super(api, kdf, params);
    this.enc = enc;
  }

  public async seal(
    data: ArrayBuffer,
    aad: ArrayBuffer = EMPTY,
  ): Promise<ArrayBuffer> {
    let ct: ArrayBuffer;
    try {
      ct = await this._ctx.key.seal(this.computeNonce(this._ctx), data, aad);
    } catch (e: unknown) {
      throw new errors.SealError(e);
    }
    this.incrementSeq(this._ctx);
    return ct;
  }
}
