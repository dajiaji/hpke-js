import type { KdfInterface } from "@hpke/common";
import {
  ExportError,
  INPUT_LENGTH_LIMIT,
  InvalidParamError,
} from "@hpke/common";

import type { Encapsulator } from "./interfaces/encapsulator.ts";
import type { EncryptionContext } from "./interfaces/encryptionContext.ts";

import { emitNotSupported } from "./utils/emitNotSupported.ts";

// b"sec"
const LABEL_SEC = new Uint8Array([115, 101, 99]);

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
    return await emitNotSupported<ArrayBuffer>();
  }

  public async open(
    _data: ArrayBuffer,
    _aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await emitNotSupported<ArrayBuffer>();
  }

  public async export(
    exporterContext: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer> {
    if (exporterContext.byteLength > INPUT_LENGTH_LIMIT) {
      throw new InvalidParamError("Too long exporter context");
    }
    try {
      return await this._kdf.labeledExpand(
        this.exporterSecret,
        LABEL_SEC,
        new Uint8Array(exporterContext),
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
