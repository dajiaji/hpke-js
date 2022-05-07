import type { SenderContextParams } from './interfaces/senderContextParams';
import type { RecipientContextParams } from './interfaces/recipientContextParams';

import { Kem } from './identifiers';
import { KdfCommon } from './kdfCommon';
import { isCryptoKeyPair, i2Osp, concat, concat3 } from './utils';

import * as consts from './consts';
import * as errors from './errors';

export class KemContext extends KdfCommon {

  private _algKeyGen: EcKeyGenParams;
  private _nSecret: number;
  private _nPk: number;
  private _nDh: number;

  public constructor(crypto: SubtleCrypto, kem: Kem) {
    const suiteId = new Uint8Array(5);
    suiteId.set(consts.SUITE_ID_HEADER_KEM, 0);
    suiteId.set(i2Osp(kem, 2), 3);

    let algHash: HmacKeyGenParams;
    switch (kem) {
      case Kem.DhkemP256HkdfSha256:
        algHash = { name: 'HMAC', hash: 'SHA-256', length: 256 };
        break;
      case Kem.DhkemP384HkdfSha384:
        algHash = { name: 'HMAC', hash: 'SHA-384', length: 384 };
        break;
      case Kem.DhkemP521HkdfSha512:
        algHash = { name: 'HMAC', hash: 'SHA-512', length: 512 };
        break;
    }
    super(crypto, suiteId, algHash);

    switch (kem) {
      case Kem.DhkemP256HkdfSha256:
        this._algKeyGen = { name: 'ECDH', namedCurve: 'P-256' };
        this._nSecret = 32;
        this._nPk = 65;
        this._nDh = 32;
        break;
      case Kem.DhkemP384HkdfSha384:
        this._algKeyGen = { name: 'ECDH', namedCurve: 'P-384' };
        this._nSecret = 48;
        this._nPk = 97;
        this._nDh = 48;
        break;
      case Kem.DhkemP521HkdfSha512:
        this._algKeyGen = { name: 'ECDH', namedCurve: 'P-521' };
        this._nSecret = 64;
        this._nPk = 133;
        this._nDh = 66;
        break;
    }
    return;
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      return await this._crypto.generateKey(this._algKeyGen, true, consts.KEM_USAGES);
    } catch (e: unknown) {
      throw new errors.DeriveKeyPairError(e);
    }
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    throw new errors.NotSupportedError('deriveKeyPair not supported');
  }

  public async encap(params: SenderContextParams): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    const ke = params.nonEphemeralKeyPair === undefined ? await this.generateKeyPair() : params.nonEphemeralKeyPair;
    const enc = await this._crypto.exportKey('raw', ke.publicKey);
    const pkrm = await this._crypto.exportKey('raw', params.recipientPublicKey);

    try {
      let dh: Uint8Array;
      if (params.senderKey === undefined) {
        dh = await this.dh(ke.privateKey, params.recipientPublicKey);
      } else {
        const sks = isCryptoKeyPair(params.senderKey) ? params.senderKey.privateKey : params.senderKey;
        const dh1 = await this.dh(ke.privateKey, params.recipientPublicKey);
        const dh2 = await this.dh(sks, params.recipientPublicKey);
        dh = concat(dh1, dh2);
      }

      let kemContext: Uint8Array;
      if (params.senderKey === undefined) {
        kemContext = concat(new Uint8Array(enc), new Uint8Array(pkrm));
      } else {
        const pks = isCryptoKeyPair(params.senderKey) ? params.senderKey.publicKey : await this.derivePublicKey(params.senderKey);
        const pksm = await this._crypto.exportKey('raw', pks);
        kemContext = concat3(new Uint8Array(enc), new Uint8Array(pkrm), new Uint8Array(pksm));
      }
      const sharedSecret = await this.generateSharedSecret(dh, kemContext);
      return {
        enc: enc,
        sharedSecret: sharedSecret,
      };
    } catch (e: unknown) {
      throw new errors.EncapError(e);
    }
  }

  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const pke = await this._crypto.importKey('raw', params.enc, this._algKeyGen, true, consts.KEM_USAGES);
    const skr = isCryptoKeyPair(params.recipientKey) ? params.recipientKey.privateKey : params.recipientKey;
    const pkr = isCryptoKeyPair(params.recipientKey) ? params.recipientKey.publicKey : await this.derivePublicKey(params.recipientKey);
    const pkrm = await this._crypto.exportKey('raw', pkr);

    try {
      let dh: Uint8Array;
      if (params.senderPublicKey === undefined) {
        dh = await this.dh(skr, pke);
      } else {
        const dh1 = await this.dh(skr, pke);
        const dh2 = await this.dh(skr, params.senderPublicKey);
        dh = concat(dh1, dh2);
      }

      let kemContext: Uint8Array;
      if (params.senderPublicKey === undefined) {
        kemContext = concat(new Uint8Array(params.enc), new Uint8Array(pkrm));
      } else {
        const pksm = await this._crypto.exportKey('raw', params.senderPublicKey);
        kemContext = new Uint8Array(params.enc.byteLength + pkrm.byteLength + pksm.byteLength);
        kemContext.set(new Uint8Array(params.enc), 0);
        kemContext.set(new Uint8Array(pkrm), params.enc.byteLength);
        kemContext.set(new Uint8Array(pksm), params.enc.byteLength + pkrm.byteLength);
      }
      return await this.generateSharedSecret(dh, kemContext);
    } catch (e: unknown) {
      throw new errors.DecapError(e);
    }
  }

  private async derivePublicKey(priv: CryptoKey): Promise<CryptoKey> {
    const jwk = await this._crypto.exportKey('jwk', priv);
    delete jwk['d'];
    return await this._crypto.importKey('jwk', jwk, this._algKeyGen, true, ['deriveBits']);
  }

  private async dh(sk: CryptoKey, pk: CryptoKey): Promise<Uint8Array> {
    const bits = await this._crypto.deriveBits(
      {
        name: 'ECDH',
        public: pk,
      },
      sk,
      this._nDh * 8,
    );
    return new Uint8Array(bits);
  }

  private async generateSharedSecret(dh: Uint8Array, kemContext: Uint8Array): Promise<ArrayBuffer> {
    const labeledIkm = this.buildLabeledIkm(consts.LABEL_EAE_PRK, dh);
    const labeledInfo = this.buildLabeledInfo(consts.LABEL_SHARED_SECRET, kemContext, this._nSecret);
    return await this.extractAndExpand(consts.EMPTY, labeledIkm, labeledInfo, this._nSecret);
  }
}
