import type { KemPrimitives } from "./interfaces/kemPrimitives.ts";
import type { SenderContextParams } from "./interfaces/senderContextParams.ts";
import type { RecipientContextParams } from "./interfaces/recipientContextParams.ts";

import { Ec } from "./kemPrimitives/ec.ts";
import { X25519 } from "./kemPrimitives/x25519.ts";
import { X448 } from "./kemPrimitives/x448.ts";
import { Kem } from "./identifiers.ts";
import { KdfCommon } from "./kdfCommon.ts";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "./utils/misc.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

export class KemContext extends KdfCommon {
  private _prim: KemPrimitives;
  private _nSecret: number;

  constructor(api: SubtleCrypto, kem: Kem) {
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(kem, 2), 3);

    let algHash: HmacKeyGenParams;
    switch (kem) {
      case Kem.DhkemP256HkdfSha256:
        algHash = { name: "HMAC", hash: "SHA-256", length: 256 };
        break;
      case Kem.DhkemP384HkdfSha384:
        algHash = { name: "HMAC", hash: "SHA-384", length: 384 };
        break;
      case Kem.DhkemP521HkdfSha512:
        algHash = { name: "HMAC", hash: "SHA-512", length: 512 };
        break;
      case Kem.DhkemX25519HkdfSha256:
        algHash = { name: "HMAC", hash: "SHA-256", length: 256 };
        break;
      default:
        // case Kem.DhkemX448HkdfSha512:
        algHash = { name: "HMAC", hash: "SHA-512", length: 512 };
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
      case Kem.DhkemX25519HkdfSha256:
        this._prim = new X25519(this);
        this._nSecret = 32;
        break;
      default:
        // case Kem.DhkemX448HkdfSha512:
        this._prim = new X448(this);
        this._nSecret = 64;
        break;
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    return await this._prim.generateKeyPair();
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    try {
      return await this._prim.deriveKeyPair(ikm);
    } catch (e: unknown) {
      throw new errors.DeriveKeyPairError(e);
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
    const labeledIkm = this.buildLabeledIkm(consts.LABEL_EAE_PRK, dh);
    const labeledInfo = this.buildLabeledInfo(
      consts.LABEL_SHARED_SECRET,
      kemContext,
      this._nSecret,
    );
    return await this.extractAndExpand(
      consts.EMPTY,
      labeledIkm,
      labeledInfo,
      this._nSecret,
    );
  }
}
