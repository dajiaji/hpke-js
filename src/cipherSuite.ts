import type { CipherSuiteParams } from './interfaces/cipherSuiteParams';
import type { RecipientContextParams } from './interfaces/recipientContextParams';
import type { SenderContextParams } from './interfaces/senderContextParams';
import type { RecipientContextInterface, SenderContextInterface } from './interfaces/encryptionContextInterface';

import { Aead, Kdf, Kem, Mode } from './identifiers';
import { RecipientExporterContext, SenderExporterContext } from './exporterContext';
import { KdfContext } from './kdfContext';
import { KemContext } from './kemContext';
import { RecipientContext } from './recipientContext';
import { SenderContext } from './senderContext';
import { loadSubtleCrypto } from './webCrypto';

export class CipherSuite {
  public readonly kem: Kem;
  public readonly kdf: Kdf;
  public readonly aead: Aead;

  private _kem: KemContext | undefined = undefined;
  private _kdf: KdfContext | undefined = undefined;

  public constructor(params: CipherSuiteParams) {
    this.kem = params.kem;
    this.kdf = params.kdf;
    this.aead = params.aead;
    return;
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    if (this._kem === undefined || this._kdf === undefined) {
      const crypto = await loadSubtleCrypto();
      this._kem = new KemContext(crypto, this.kem);
      this._kdf = new KdfContext(crypto, { kem: this.kem, kdf: this.kdf, aead: this.aead });
    }
    return await this._kem.generateKeyPair();
  }

  public async createSenderContext(params: SenderContextParams): Promise<SenderContextInterface> {
    const crypto = await loadSubtleCrypto();
    if (this._kem === undefined || this._kdf === undefined) {
      this._kem = new KemContext(crypto, this.kem);
      this._kdf = new KdfContext(crypto, { kem: this.kem, kdf: this.kdf, aead: this.aead });
    }

    const dh = await this._kem.encap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext(crypto, { kem: this.kem, kdf: this.kdf, aead: this.aead });
    const aeadParams = await this._kdf.keySchedule(mode, dh.sharedSecret, params);
    if (aeadParams.key === undefined) {
      return new SenderExporterContext(crypto, kdf, aeadParams.exporterSecret, dh.enc);
    }
    return new SenderContext(crypto, kdf, aeadParams, dh.enc);
  }

  public async createRecipientContext(params: RecipientContextParams): Promise<RecipientContextInterface> {
    const crypto = await loadSubtleCrypto();
    if (this._kem === undefined || this._kdf === undefined) {
      this._kem = new KemContext(crypto, this.kem);
      this._kdf = new KdfContext(crypto, { kem: this.kem, kdf: this.kdf, aead: this.aead });
    }

    const sharedSecret = await this._kem.decap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderPublicKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext(crypto, { kem: this.kem, kdf: this.kdf, aead: this.aead });
    const aeadParams = await this._kdf.keySchedule(mode, sharedSecret, params);
    if (aeadParams.key === undefined) {
      return new RecipientExporterContext(crypto, kdf, aeadParams.exporterSecret);
    }
    return new RecipientContext(crypto, kdf, aeadParams);
  }
}
