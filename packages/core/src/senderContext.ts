import type { KdfInterface, SenderContextParams } from "@hpke/common";
import { EMPTY, SealError, toArrayBuffer } from "@hpke/common";

import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { Encapsulator } from "./interfaces/encapsulator.ts";
import type { SenderContext } from "./interfaces/encryptionContext.ts";
import { EncryptionContextImpl } from "./encryptionContext.ts";
import { ExporterContextImpl } from "./exporterContext.ts";
import { checkParams, keySchedule, type Suite } from "./keySchedule.ts";
import { Mutex } from "./mutex.ts";

// This module holds everything specific to senders. It must not be imported
// by recipientContext.ts or the modules shared with it.

export class SenderExporterContextImpl extends ExporterContextImpl
  implements Encapsulator {
  public readonly enc: ArrayBuffer;

  public constructor(
    kdf: KdfInterface,
    exporterSecret: ArrayBuffer,
    enc: ArrayBuffer,
  ) {
    super(kdf, exporterSecret);
    this.enc = enc;
  }
}

export class SenderContextImpl extends EncryptionContextImpl
  implements Encapsulator {
  public readonly enc: ArrayBuffer;
  #mutex?: Mutex;

  constructor(
    kdf: KdfInterface,
    params: Required<AeadParams>,
    enc: ArrayBuffer,
  ) {
    super(kdf, params);
    this.enc = enc;
  }

  override async seal(
    data: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView = EMPTY.buffer as ArrayBuffer,
  ): Promise<ArrayBuffer> {
    this.#mutex ??= new Mutex();
    const release = await this.#mutex.lock();
    let ct: ArrayBuffer;
    try {
      ct = await this._ctx.key.seal(
        this.computeNonce(this._ctx),
        toArrayBuffer(data),
        toArrayBuffer(aad),
      );
    } catch (e: unknown) {
      throw new SealError(e);
    } finally {
      release();
    }
    this.incrementSeq(this._ctx);
    return ct;
  }
}

/**
 * Creates an encryption context for a sender on an initialized suite.
 */
export async function setupSender(
  suite: Suite,
  params: SenderContextParams,
): Promise<SenderContext> {
  const auth = params.senderKey !== undefined;
  checkParams(suite.kem, params, auth);
  const dh = await suite.kem.encap(params);
  const res = await keySchedule(suite, params, dh.sharedSecret, auth);
  return res.key === undefined
    ? new SenderExporterContextImpl(suite.kdf, res.exporterSecret, dh.enc)
    : new SenderContextImpl(suite.kdf, res as Required<AeadParams>, dh.enc);
}
