import type { CipherSuiteParams } from './interfaces/cipherSuiteParams';
import type { CipherSuiteSealResponse } from './interfaces/responses';
import type { RecipientContextParams } from './interfaces/recipientContextParams';
import type { SenderContextParams } from './interfaces/senderContextParams';
import type { RecipientContextInterface, SenderContextInterface } from './interfaces/encryptionContextInterface';

import { EMPTY } from './consts';
import { RecipientExporterContext, SenderExporterContext } from './exporterContext';
import { Aead, Kdf, Kem, Mode } from './identifiers';
import { KdfContext } from './kdfContext';
import { KemContext } from './kemContext';
import { RecipientContext } from './recipientContext';
import { SenderContext } from './senderContext';
import { loadSubtleCrypto } from './webCrypto';

import * as errors from './errors';

export class CipherSuite {
  public readonly kem: Kem;
  public readonly kdf: Kdf;
  public readonly aead: Aead;

  private _ctx: CipherSuiteParams;
  private _kem: KemContext | undefined = undefined;
  private _kdf: KdfContext | undefined = undefined;

  constructor(params: CipherSuiteParams) {
    switch (params.kem) {
      case Kem.DhkemP256HkdfSha256:
      case Kem.DhkemP384HkdfSha384:
      case Kem.DhkemP521HkdfSha512:
        break;
      default:
        throw new errors.InvalidParamError('Invalid KEM id');
    }
    this.kem = params.kem;

    switch (params.kdf) {
      case Kdf.HkdfSha256:
      case Kdf.HkdfSha384:
      case Kdf.HkdfSha512:
        break;
      default:
        throw new errors.InvalidParamError('Invalid KDF id');
    }
    this.kdf = params.kdf;

    switch (params.aead) {
      case Aead.Aes128Gcm:
      case Aead.Aes256Gcm:
      case Aead.ExportOnly:
        break;
      default:
        throw new errors.InvalidParamError('Invalid AEAD id');
    }
    this.aead = params.aead;
    this._ctx = { kem: this.kem, kdf: this.kdf, aead: this.aead };
    return;
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    await this.setup();
    return await (this._kem as KemContext).generateKeyPair();
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    await this.setup();
    return await (this._kem as KemContext).deriveKeyPair(ikm);
  }

  public async createSenderContext(params: SenderContextParams): Promise<SenderContextInterface> {
    const api = await this.setup();

    const dh = await (this._kem as KemContext).encap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext(api, this._ctx);
    const res = await (this._kdf as KdfContext).keySchedule(mode, dh.sharedSecret, params);
    if (res.key === undefined) {
      return new SenderExporterContext(api, kdf, res.exporterSecret, dh.enc);
    }
    return new SenderContext(api, kdf, res, dh.enc);
  }

  public async createRecipientContext(params: RecipientContextParams): Promise<RecipientContextInterface> {
    const api = await this.setup();

    const sharedSecret = await (this._kem as KemContext).decap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderPublicKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext(api, this._ctx);
    const res = await (this._kdf as KdfContext).keySchedule(mode, sharedSecret, params);
    if (res.key === undefined) {
      return new RecipientExporterContext(api, kdf, res.exporterSecret);
    }
    return new RecipientContext(api, kdf, res);
  }

  public async seal(params: SenderContextParams, pt: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<CipherSuiteSealResponse> {
    const ctx = await this.createSenderContext(params);
    return {
      ct: await ctx.seal(pt, aad),
      enc: ctx.enc,
    };
  }

  public async open(params: RecipientContextParams, ct: ArrayBuffer, aad: ArrayBuffer = EMPTY): Promise<ArrayBuffer> {
    const ctx = await this.createRecipientContext(params);
    return await ctx.open(ct, aad);
  }

  private async setup(): Promise<SubtleCrypto> {
    const api = await loadSubtleCrypto();
    if (this._kem === undefined || this._kdf === undefined) {
      this._kem = new KemContext(api, this.kem);
      this._kdf = new KdfContext(api, this._ctx);
    }
    return api;
  }
}
