import type { KdfInterface } from "@hpke/common";
import {
  ExportError,
  INPUT_LENGTH_LIMIT,
  InvalidParamError,
  NotSupportedError,
  toArrayBuffer,
} from "@hpke/common";

import type { Encapsulator } from "./interfaces/encapsulator.ts";
import type { EncryptionContext } from "./interfaces/encryptionContext.ts";

// b"sec"
const LABEL_SEC = new Uint8Array([115, 101, 99]);

export class ExporterContextImpl implements EncryptionContext {
  protected readonly exporterSecret: ArrayBuffer;
  private _kdf: KdfInterface;

  constructor(kdf: KdfInterface, exporterSecret: ArrayBuffer) {
    this._kdf = kdf;
    this.exporterSecret = exporterSecret;
  }

  public seal(
    _data: ArrayBufferLike | ArrayBufferView,
    _aad: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    return Promise.reject(new NotSupportedError("Not supported"));
  }

  public open(
    _data: ArrayBufferLike | ArrayBufferView,
    _aad: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    return Promise.reject(new NotSupportedError("Not supported"));
  }

  public async export(
    exporterContext: ArrayBufferLike | ArrayBufferView,
    len: number,
  ): Promise<ArrayBuffer> {
    const rawExporterContext = toArrayBuffer(exporterContext);
    if (rawExporterContext.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long exporter context");
    }
    try {
      return await this._kdf.labeledExpand(
        this.exporterSecret,
        LABEL_SEC,
        new Uint8Array(rawExporterContext),
        len,
      );
    } catch (e: unknown) {
      throw new ExportError(e);
    }
  }
}

export class RecipientExporterContextImpl extends ExporterContextImpl {}

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
