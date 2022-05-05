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

export class CipherSuite {
  public readonly kem: Kem;
  public readonly kdf: Kdf;
  public readonly aead: Aead;

  private _kem: KemContext;
  private _kdf: KdfContext;

  public constructor(params: CipherSuiteParams) {
    this.kem = params.kem;
    this.kdf = params.kdf;
    this.aead = params.aead;

    this._kem = new KemContext(params.kem);
    this._kdf = new KdfContext(params);
    return;
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    return await this._kem.generateKeyPair();
  }

  public async createSenderContext(params: SenderContextParams): Promise<SenderContextInterface> {
    // const dh = await this._kem.encap(params.recipientPublicKey, params.nonEphemeralKeyPair);
    const dh = await this._kem.encap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext({ kem: this.kem, kdf: this.kdf, aead: this.aead });
    const aeadParams = await this._kdf.keySchedule(mode, dh.sharedSecret, params);
    if (aeadParams.key === undefined) {
      return new SenderExporterContext(kdf, aeadParams.exporterSecret, dh.enc);
    }
    return new SenderContext(kdf, aeadParams, dh.enc);
  }

  public async createRecipientContext(params: RecipientContextParams): Promise<RecipientContextInterface> {

    const sharedSecret = await this._kem.decap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderPublicKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext({ kem: this.kem, kdf: this.kdf, aead: this.aead });
    const aeadParams = await this._kdf.keySchedule(mode, sharedSecret, params);
    if (aeadParams.key === undefined) {
      return new RecipientExporterContext(kdf, aeadParams.exporterSecret);
    }
    return new RecipientContext(kdf, aeadParams);
  }
}
