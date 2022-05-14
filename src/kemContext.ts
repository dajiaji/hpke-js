import type { KemPrimitives } from './interfaces/kemPrimitives';
import type { SenderContextParams } from './interfaces/senderContextParams';
import type { RecipientContextParams } from './interfaces/recipientContextParams';

import { Ec } from './kemPrimitives/ec';
import { Kem } from './identifiers';
import { KdfCommon } from './kdfCommon';
import { isCryptoKeyPair, i2Osp, concat, concat3 } from './utils/misc';

import * as consts from './consts';
import * as errors from './errors';

export class KemContext extends KdfCommon {

  private _prim: KemPrimitives;
  private _nSecret: number;

  constructor(api: SubtleCrypto, kem: Kem) {
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
    super(api, suiteId, algHash);

    switch (kem) {
      case Kem.DhkemP256HkdfSha256:
        this._prim = new Ec(kem, this, this._api);
        this._nSecret = 32;
        break;
      case Kem.DhkemP384HkdfSha384:
        this._prim = new Ec(kem, this, this._api);
        this._nSecret = 48;
        break;
      case Kem.DhkemP521HkdfSha512:
        this._prim = new Ec(kem, this, this._api);
        this._nSecret = 64;
        break;
    }
    return;
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    return await this._prim.generateKeyPair();
  }

  public async deriveKey(ikm: ArrayBuffer): Promise<ArrayBuffer> {
    try {
      return await this._prim.deriveKey(ikm);
    } catch (e: unknown) {
      throw new errors.DeriveKeyPairError(e);
    }
  }

  public async encap(params: SenderContextParams): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    try {
      const ke = params.nonEphemeralKeyPair === undefined
        ? await this.generateKeyPair() : params.nonEphemeralKeyPair;
      const enc = await this._prim.serializePublicKey(ke.publicKey);
      const pkrm = await this._prim.serializePublicKey(params.recipientPublicKey);

      let dh: Uint8Array;
      if (params.senderKey === undefined) {
        dh = new Uint8Array(await this._prim.dh(ke.privateKey, params.recipientPublicKey));
      } else {
        const sks = isCryptoKeyPair(params.senderKey) ? params.senderKey.privateKey : params.senderKey;
        const dh1 = new Uint8Array(await this._prim.dh(ke.privateKey, params.recipientPublicKey));
        const dh2 = new Uint8Array(await this._prim.dh(sks, params.recipientPublicKey));
        dh = concat(dh1, dh2);
      }

      let kemContext: Uint8Array;
      if (params.senderKey === undefined) {
        kemContext = concat(new Uint8Array(enc), new Uint8Array(pkrm));
      } else {
        const pks = isCryptoKeyPair(params.senderKey)
          ? params.senderKey.publicKey : await this._prim.derivePublicKey(params.senderKey);
        const pksm = await this._prim.serializePublicKey(pks);
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
    let pke: CryptoKey;
    try {
      pke = await this._prim.deserializePublicKey(params.enc);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }

    try {
      const skr = isCryptoKeyPair(params.recipientKey)
        ? params.recipientKey.privateKey : params.recipientKey;
      const pkr = isCryptoKeyPair(params.recipientKey)
        ? params.recipientKey.publicKey : await this._prim.derivePublicKey(params.recipientKey);
      const pkrm = await this._prim.serializePublicKey(pkr);

      let dh: Uint8Array;
      if (params.senderPublicKey === undefined) {
        dh = new Uint8Array(await this._prim.dh(skr, pke));
      } else {
        const dh1 = new Uint8Array(await this._prim.dh(skr, pke));
        const dh2 = new Uint8Array(await this._prim.dh(skr, params.senderPublicKey));
        dh = concat(dh1, dh2);
      }

      let kemContext: Uint8Array;
      if (params.senderPublicKey === undefined) {
        kemContext = concat(new Uint8Array(params.enc), new Uint8Array(pkrm));
      } else {
        const pksm = await this._prim.serializePublicKey(params.senderPublicKey);
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

  private async generateSharedSecret(dh: Uint8Array, kemContext: Uint8Array): Promise<ArrayBuffer> {
    const labeledIkm = this.buildLabeledIkm(consts.LABEL_EAE_PRK, dh);
    const labeledInfo = this.buildLabeledInfo(consts.LABEL_SHARED_SECRET, kemContext, this._nSecret);
    return await this.extractAndExpand(consts.EMPTY, labeledIkm, labeledInfo, this._nSecret);
  }
}
