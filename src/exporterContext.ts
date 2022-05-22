import type { Encapsulator } from './interfaces/encapsulator';
import type { EncryptionContextInterface } from './interfaces/encryptionContextInterface';
import type { KdfContext } from './kdfContext';

import { WebCrypto } from './webCrypto';

import * as consts from './consts';
import * as errors from './errors';

export class ExporterContext extends WebCrypto implements EncryptionContextInterface {

  protected readonly exporterSecret: ArrayBuffer;
  private _kdf: KdfContext;

  constructor(api: SubtleCrypto, kdf: KdfContext, exporterSecret: ArrayBuffer) {
    super(api);
    this._kdf = kdf;
    this.exporterSecret = exporterSecret;
    return;
  }

  public async seal(_data: ArrayBuffer, _aad: ArrayBuffer): Promise<ArrayBuffer> {
    throw new errors.NotSupportedError('Not available on export-only mode');
  }

  public async open(_data: ArrayBuffer, _aad: ArrayBuffer): Promise<ArrayBuffer> {
    throw new errors.NotSupportedError('Not available on export-only mode');
  }

  public async setupBidirectional(_keySeed: ArrayBuffer, _nonceSeed: ArrayBuffer): Promise<void> {
    throw new errors.NotSupportedError('Not available on export-only mode');
  }

  public async export(exporterContext: ArrayBuffer, len: number): Promise<ArrayBuffer> {
    if (exporterContext.byteLength > consts.INPUT_LENGTH_LIMIT) {
      throw new errors.InvalidParamError('Too long exporter context');
    }
    try {
      return await this._kdf.labeledExpand(this.exporterSecret, consts.LABEL_SEC, new Uint8Array(exporterContext), len);
    } catch (e: unknown) {
      throw new errors.ExportError(e);
    }
  }
}

export class RecipientExporterContext extends ExporterContext {}

export class SenderExporterContext extends ExporterContext implements Encapsulator {

  public readonly enc: ArrayBuffer;

  public constructor(api: SubtleCrypto, kdf: KdfContext, exporterSecret: ArrayBuffer, enc: ArrayBuffer) {
    super(api, kdf, exporterSecret);
    this.enc = enc;
    return;
  }
}
