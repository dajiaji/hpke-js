import type { Encapsulator } from "./interfaces/encapsulator.ts";
import type { EncryptionContextInterface } from "./interfaces/encryptionContextInterface.ts";
import type { KdfContext } from "./kdfContext.ts";

import { WebCrypto } from "./webCrypto.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

export class ExporterContext extends WebCrypto
  implements EncryptionContextInterface {
  protected readonly exporterSecret: ArrayBuffer;
  private _kdf: KdfContext;

  constructor(api: SubtleCrypto, kdf: KdfContext, exporterSecret: ArrayBuffer) {
    super(api);
    this._kdf = kdf;
    this.exporterSecret = exporterSecret;
    return;
  }

  public async seal(
    _data: ArrayBuffer,
    _aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this._emitError1();
  }

  public async open(
    _data: ArrayBuffer,
    _aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this._emitError1();
  }

  public async setupBidirectional(
    _keySeed: ArrayBuffer,
    _nonceSeed: ArrayBuffer,
  ): Promise<void> {
    return await this._emitError2();
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

  private _emitError1(): Promise<ArrayBuffer> {
    return new Promise((_resolve, reject) => {
      reject(new errors.NotSupportedError("Not available on export-only mode"));
    });
  }

  private _emitError2(): Promise<void> {
    return new Promise((_resolve, reject) => {
      reject(new errors.NotSupportedError("Not available on export-only mode"));
    });
  }
}

export class RecipientExporterContext extends ExporterContext {}

export class SenderExporterContext extends ExporterContext
  implements Encapsulator {
  public readonly enc: ArrayBuffer;

  public constructor(
    api: SubtleCrypto,
    kdf: KdfContext,
    exporterSecret: ArrayBuffer,
    enc: ArrayBuffer,
  ) {
    super(api, kdf, exporterSecret);
    this.enc = enc;
    return;
  }
}
