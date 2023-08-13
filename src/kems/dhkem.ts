import type { KdfInterface } from "../interfaces/kdfInterface.ts";
import type { KemInterface } from "../interfaces/kemInterface.ts";
import type { DhkemPrimitives } from "../interfaces/dhkemPrimitives.ts";
import type { SenderContextParams } from "../interfaces/senderContextParams.ts";
import type { RecipientContextParams } from "../interfaces/recipientContextParams.ts";

import { KemId } from "../identifiers.ts";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "../utils/misc.ts";

import { EMPTY, INPUT_LENGTH_LIMIT } from "../consts.ts";
import * as errors from "../errors.ts";

// b"KEM"
const SUITE_ID_HEADER_KEM = new Uint8Array([75, 69, 77, 0, 0]);
// b"eae_prk"
const LABEL_EAE_PRK = new Uint8Array([101, 97, 101, 95, 112, 114, 107]);
// b"shared_secret"
// deno-fmt-ignore
const LABEL_SHARED_SECRET = new Uint8Array([
  115, 104, 97, 114, 101, 100, 95, 115, 101, 99,
  114, 101, 116,
]);

export class Dhkem implements KemInterface {
  public readonly id: KemId;
  public readonly secretSize: number = 0;
  public readonly encSize: number = 0;
  public readonly publicKeySize: number = 0;
  public readonly privateKeySize: number = 0;
  protected _prim: DhkemPrimitives;
  protected _kdf: KdfInterface;

  constructor(id: KemId, prim: DhkemPrimitives, kdf: KdfInterface) {
    this.id = id;
    this._prim = prim;
    this._kdf = kdf;
    const suiteId = new Uint8Array(SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(this.id, 2), 3);
    this._kdf.init(suiteId);
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    return await this._prim.generateKeyPair();
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    if (ikm.byteLength > INPUT_LENGTH_LIMIT) {
      throw new errors.InvalidParamError("Too long ikm");
    }
    return await this._prim.deriveKeyPair(ikm);
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this._prim.serializePublicKey(key);
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._prim.deserializePublicKey(key);
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this._prim.serializePrivateKey(key);
  }

  public async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._prim.deserializePrivateKey(key);
  }

  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic = true,
  ): Promise<CryptoKey> {
    return await this._prim.importKey(format, key, isPublic);
  }

  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    const ke = params.nonEphemeralKeyPair === undefined
      ? await this.generateKeyPair()
      : params.nonEphemeralKeyPair;
    const enc = await this._prim.serializePublicKey(ke.publicKey);
    const pkrm = await this._prim.serializePublicKey(
      params.recipientPublicKey,
    );

    try {
      let dh: Uint8Array;
      if (params.senderKey === undefined) {
        dh = new Uint8Array(
          await this._prim.dh(ke.privateKey, params.recipientPublicKey),
        );
      } else {
        const sks = isCryptoKeyPair(params.senderKey)
          ? params.senderKey.privateKey
          : params.senderKey;
        const dh1 = new Uint8Array(
          await this._prim.dh(ke.privateKey, params.recipientPublicKey),
        );
        const dh2 = new Uint8Array(
          await this._prim.dh(sks, params.recipientPublicKey),
        );
        dh = concat(dh1, dh2);
      }

      let kemContext: Uint8Array;
      if (params.senderKey === undefined) {
        kemContext = concat(new Uint8Array(enc), new Uint8Array(pkrm));
      } else {
        const pks = isCryptoKeyPair(params.senderKey)
          ? params.senderKey.publicKey
          : await this._prim.derivePublicKey(params.senderKey);
        const pksm = await this._prim.serializePublicKey(pks);
        kemContext = concat3(
          new Uint8Array(enc),
          new Uint8Array(pkrm),
          new Uint8Array(pksm),
        );
      }
      const sharedSecret = await this._generateSharedSecret(dh, kemContext);
      return {
        enc: enc,
        sharedSecret: sharedSecret,
      };
    } catch (e: unknown) {
      throw new errors.EncapError(e);
    }
  }

  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const pke = await this._prim.deserializePublicKey(params.enc);
    const skr = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.privateKey
      : params.recipientKey;
    const pkr = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.publicKey
      : await this._prim.derivePublicKey(params.recipientKey);
    const pkrm = await this._prim.serializePublicKey(pkr);

    try {
      let dh: Uint8Array;
      if (params.senderPublicKey === undefined) {
        dh = new Uint8Array(await this._prim.dh(skr, pke));
      } else {
        const dh1 = new Uint8Array(await this._prim.dh(skr, pke));
        const dh2 = new Uint8Array(
          await this._prim.dh(skr, params.senderPublicKey),
        );
        dh = concat(dh1, dh2);
      }

      let kemContext: Uint8Array;
      if (params.senderPublicKey === undefined) {
        kemContext = concat(new Uint8Array(params.enc), new Uint8Array(pkrm));
      } else {
        const pksm = await this._prim.serializePublicKey(
          params.senderPublicKey,
        );
        kemContext = new Uint8Array(
          params.enc.byteLength + pkrm.byteLength + pksm.byteLength,
        );
        kemContext.set(new Uint8Array(params.enc), 0);
        kemContext.set(new Uint8Array(pkrm), params.enc.byteLength);
        kemContext.set(
          new Uint8Array(pksm),
          params.enc.byteLength + pkrm.byteLength,
        );
      }
      return await this._generateSharedSecret(dh, kemContext);
    } catch (e: unknown) {
      throw new errors.DecapError(e);
    }
  }

  private async _generateSharedSecret(
    dh: Uint8Array,
    kemContext: Uint8Array,
  ): Promise<ArrayBuffer> {
    const labeledIkm = this._kdf.buildLabeledIkm(LABEL_EAE_PRK, dh);
    const labeledInfo = this._kdf.buildLabeledInfo(
      LABEL_SHARED_SECRET,
      kemContext,
      this.secretSize,
    );
    return await this._kdf.extractAndExpand(
      EMPTY,
      labeledIkm,
      labeledInfo,
      this.secretSize,
    );
  }
}
