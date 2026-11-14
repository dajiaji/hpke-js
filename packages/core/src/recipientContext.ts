import type { RecipientContextParams } from "@hpke/common";
import { EMPTY, OpenError, toArrayBuffer } from "@hpke/common";

import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { RecipientContext } from "./interfaces/encryptionContext.ts";
import { EncryptionContextImpl } from "./encryptionContext.ts";
import { ExporterContextImpl } from "./exporterContext.ts";
import { checkParams, keySchedule, type Suite } from "./keySchedule.ts";
import { Mutex } from "./mutex.ts";

// This module holds everything specific to recipients. It must not be
// imported by senderContext.ts or the modules shared with it.

export class RecipientContextImpl extends EncryptionContextImpl {
  #mutex?: Mutex;

  override async open(
    data: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView = EMPTY.buffer as ArrayBuffer,
  ): Promise<ArrayBuffer> {
    this.#mutex ??= new Mutex();
    const release = await this.#mutex.lock();
    let pt: ArrayBuffer;
    try {
      pt = await this._ctx.key.open(
        this.computeNonce(this._ctx),
        toArrayBuffer(data),
        toArrayBuffer(aad),
      );
    } catch (e: unknown) {
      throw new OpenError(e);
    } finally {
      release();
    }
    this.incrementSeq(this._ctx);
    return pt;
  }
}

/**
 * Creates an encryption context for a recipient on an initialized suite.
 */
export async function setupRecipient(
  suite: Suite,
  params: RecipientContextParams,
): Promise<RecipientContext> {
  const auth = params.senderPublicKey !== undefined;
  checkParams(suite.kem, params, auth);
  const sharedSecret = await suite.kem.decap(params);
  const res = await keySchedule(suite, params, sharedSecret, auth);
  return res.key === undefined
    ? new ExporterContextImpl(suite.kdf, res.exporterSecret)
    : new RecipientContextImpl(suite.kdf, res as Required<AeadParams>);
}
