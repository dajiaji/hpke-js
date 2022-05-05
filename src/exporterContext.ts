import type { Encapsulator } from './interfaces/encapsulator';
import type { EncryptionContextInterface } from './interfaces/encryptionContextInterface';
import type { KdfContext } from './kdfContext';

import * as consts from './consts';
import * as errors from './errors';

export class ExporterContext implements EncryptionContextInterface {

  protected readonly exporterSecret: ArrayBuffer;
  private _kdf: KdfContext;

  public constructor(kdf: KdfContext, exporterSecret: ArrayBuffer) {
    this._kdf = kdf;
    this.exporterSecret = exporterSecret;
    return;
  }

  public async seal(data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    throw new errors.SealError('Not available on export-only mode');
  }

  public async open(data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    throw new errors.OpenError('Not available on export-only mode');
  }

  public async export(info: ArrayBuffer, len: number): Promise<ArrayBuffer> {
    try {
      return await this._kdf.labeledExpand(this.exporterSecret, consts.LABEL_SEC, new Uint8Array(info), len);
    } catch (e: unknown) {
      throw new errors.ExportError(e);
    }
  }
}

export class RecipientExporterContext extends ExporterContext {}

export class SenderExporterContext extends ExporterContext implements Encapsulator {

  public readonly enc: ArrayBuffer;

  public constructor(kdf: KdfContext, exporterSecret: ArrayBuffer, enc: ArrayBuffer) {
    super(kdf, exporterSecret);
    this.enc = enc;
    return;
  }
}
