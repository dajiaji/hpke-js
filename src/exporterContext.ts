import type { Encapsulator } from "./interfaces/encapsulator.ts";
import type { EncryptionContext } from "./interfaces/encryptionContext.ts";
import type { KdfInterface } from "./interfaces/kdfInterface.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

export class ExporterContextImpl implements EncryptionContext {
  protected _api: SubtleCrypto;
  protected readonly exporterSecret: ArrayBuffer;
  private _kdf: KdfInterface;

  constructor(
    api: SubtleCrypto,
    kdf: KdfInterface,
    exporterSecret: ArrayBuffer,
  ) {
    this._api = api;
    this._kdf = kdf;
    this.exporterSecret = exporterSecret;
  }

  public async seal(
    _data: ArrayBuffer,
    _aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this._emitError();
  }

  public async open(
    _data: ArrayBuffer,
    _aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this._emitError();
  }

  public async export(
    exporterContext: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer> {
    if (exporterContext.byteLength > consts.INPUT_LENGTH_LIMIT) {
      throw new errors.InvalidParamError("Too long exporter context");
    }
    try {
      return await this._kdf.labeledExpand(
        this.exporterSecret,
        consts.LABEL_SEC,
        new Uint8Array(exporterContext),
        len,
      );
    } catch (e: unknown) {
      throw new errors.ExportError(e);
    }
  }

  private _emitError(): Promise<ArrayBuffer> {
    return new Promise((_resolve, reject) => {
      reject(new errors.NotSupportedError("Not available"));
    });
  }
}

export class RecipientExporterContextImpl extends ExporterContextImpl {}

export class SenderExporterContextImpl extends ExporterContextImpl
  implements Encapsulator {
  public readonly enc: ArrayBuffer;

  public constructor(
    api: SubtleCrypto,
    kdf: KdfInterface,
    exporterSecret: ArrayBuffer,
    enc: ArrayBuffer,
  ) {
    super(api, kdf, exporterSecret);
    this.enc = enc;
    return;
  }
}
