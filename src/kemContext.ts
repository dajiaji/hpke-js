import type { KemInterface } from "./interfaces/kemInterface.ts";
import type { KemPrimitives } from "./interfaces/kemPrimitives.ts";
import type { SenderContextParams } from "./interfaces/senderContextParams.ts";
import type { RecipientContextParams } from "./interfaces/recipientContextParams.ts";

import { Ec } from "./kemPrimitives/ec.ts";
import { X25519 } from "./kemPrimitives/x25519.ts";
import { X448 } from "./kemPrimitives/x448.ts";
import { Kdf, Kem } from "./identifiers.ts";
import { KdfContext } from "./kdfContext.ts";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "./utils/misc.ts";
import { WebCrypto } from "./webCrypto.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

export class KemContext extends WebCrypto implements KemInterface {
  public readonly id: Kem;
  public readonly secretSize: number;
  public readonly encSize: number;
  public readonly publicKeySize: number;
  public readonly privateKeySize: number;
  private _prim: KemPrimitives;
  private _kdf: KdfContext;

  constructor(api: SubtleCrypto, kem: Kem) {
    super(api);
    this.id = kem;

    let kdfId: Kdf = Kdf.HkdfSha256;
    switch (kem) {
      case Kem.DhkemP256HkdfSha256:
        kdfId = Kdf.HkdfSha256;
        break;
      case Kem.DhkemP384HkdfSha384:
        kdfId = Kdf.HkdfSha384;
        break;
      case Kem.DhkemP521HkdfSha512:
        kdfId = Kdf.HkdfSha512;
        break;
      case Kem.DhkemX25519HkdfSha256:
        kdfId = Kdf.HkdfSha256;
        break;
      default:
        kdfId = Kdf.HkdfSha512;
        // case Kem.DhkemX448HkdfSha512:
        break;
    }

    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(kem, 2), 3);
    this._kdf = new KdfContext(this._api, kdfId, suiteId);

    switch (kem) {
      case Kem.DhkemP256HkdfSha256:
        this._prim = new Ec(kem, this._kdf, this._api);
        this.secretSize = 32;
        this.encSize = 65;
        this.publicKeySize = 65;
        this.privateKeySize = 32;
        break;
      case Kem.DhkemP384HkdfSha384:
        this._prim = new Ec(kem, this._kdf, this._api);
        this.secretSize = 48;
        this.encSize = 97;
        this.publicKeySize = 97;
        this.privateKeySize = 48;
        break;
      case Kem.DhkemP521HkdfSha512:
        this._prim = new Ec(kem, this._kdf, this._api);
        this.secretSize = 64;
        this.encSize = 133;
        this.publicKeySize = 133;
        this.privateKeySize = 66;
        break;
      case Kem.DhkemX25519HkdfSha256:
        this._prim = new X25519(this._kdf);
        this.secretSize = 32;
        this.encSize = 32;
        this.publicKeySize = 32;
        this.privateKeySize = 32;
        break;
      default:
        // case Kem.DhkemX448HkdfSha512:
        this._prim = new X448(this._kdf);
        this.secretSize = 64;
        this.encSize = 56;
        this.publicKeySize = 56;
        this.privateKeySize = 56;
        break;
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      return await this._prim.generateKeyPair();
    } catch (e: unknown) {
      throw new errors.NotSupportedError(e);
    }
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    try {
      return await this._prim.deriveKeyPair(ikm);
    } catch (e: unknown) {
      throw new errors.DeriveKeyPairError(e);
    }
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._prim.serializePublicKey(key);
    } catch (e: unknown) {
      throw new errors.SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._prim.deserializePublicKey(key);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }
  }

  public async importKey(
    format: "raw",
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    try {
      return await this._prim.importKey(format, key, isPublic);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }
  }

  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    try {
      const ke = params.nonEphemeralKeyPair === undefined
        ? await this.generateKeyPair()
        : params.nonEphemeralKeyPair;
      const enc = await this._prim.serializePublicKey(ke.publicKey);
      const pkrm = await this._prim.serializePublicKey(
        params.recipientPublicKey,
      );

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
        ? params.recipientKey.privateKey
        : params.recipientKey;
      const pkr = isCryptoKeyPair(params.recipientKey)
        ? params.recipientKey.publicKey
        : await this._prim.derivePublicKey(params.recipientKey);
      const pkrm = await this._prim.serializePublicKey(pkr);

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
      return await this.generateSharedSecret(dh, kemContext);
    } catch (e: unknown) {
      throw new errors.DecapError(e);
    }
  }

  private async generateSharedSecret(
    dh: Uint8Array,
    kemContext: Uint8Array,
  ): Promise<ArrayBuffer> {
    const labeledIkm = this._kdf.buildLabeledIkm(consts.LABEL_EAE_PRK, dh);
    const labeledInfo = this._kdf.buildLabeledInfo(
      consts.LABEL_SHARED_SECRET,
      kemContext,
      this.secretSize,
    );
    return await this._kdf.extractAndExpand(
      consts.EMPTY,
      labeledIkm,
      labeledInfo,
      this.secretSize,
    );
  }
}
