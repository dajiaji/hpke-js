import type { KemInterface } from "../interfaces/kemInterface.ts";
import type { KemPrimitives } from "../interfaces/kemPrimitives.ts";
import type { SenderContextParams } from "../interfaces/senderContextParams.ts";
import type { RecipientContextParams } from "../interfaces/recipientContextParams.ts";

import { Ec } from "./dhkemPrimitives/ec.ts";
import { X25519 } from "./dhkemPrimitives/x25519.ts";
import { X448 } from "./dhkemPrimitives/x448.ts";
import { Kdf, Kem } from "../identifiers.ts";
import { KdfContext } from "../kdfContext.ts";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "../utils/misc.ts";
import { WebCrypto } from "../webCrypto.ts";

import * as consts from "../consts.ts";
import * as errors from "../errors.ts";

export class Dhkem extends WebCrypto implements KemInterface {
  public readonly id: Kem = 0;
  public readonly secretSize: number = 0;
  public readonly encSize: number = 0;
  public readonly publicKeySize: number = 0;
  public readonly privateKeySize: number = 0;
  private _prim: KemPrimitives;
  private _kdf: KdfContext;

  constructor(api: SubtleCrypto, prim: KemPrimitives, kdf: KdfContext) {
    super(api);
    this._prim = prim;
    this._kdf = kdf;
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

export class DhkemP256HkdfSha256 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemP256HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 65;
  public readonly publicKeySize: number = 65;
  public readonly privateKeySize: number = 32;

  constructor(api: SubtleCrypto) {
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(Kem.DhkemP256HkdfSha256, 2), 3);
    const kdf = new KdfContext(api, Kdf.HkdfSha256, suiteId);
    const prim = new Ec(Kem.DhkemP256HkdfSha256, kdf, api);
    super(api, prim, kdf);
  }
}

export class DhkemP384HkdfSha384 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemP384HkdfSha384;
  public readonly secretSize: number = 48;
  public readonly encSize: number = 97;
  public readonly publicKeySize: number = 97;
  public readonly privateKeySize: number = 48;

  constructor(api: SubtleCrypto) {
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(Kem.DhkemP384HkdfSha384, 2), 3);
    const kdf = new KdfContext(api, Kdf.HkdfSha384, suiteId);
    const prim = new Ec(Kem.DhkemP384HkdfSha384, kdf, api);
    super(api, prim, kdf);
  }
}

export class DhkemP521HkdfSha512 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemP521HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 133;
  public readonly publicKeySize: number = 133;
  public readonly privateKeySize: number = 64;

  constructor(api: SubtleCrypto) {
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(Kem.DhkemP521HkdfSha512, 2), 3);
    const kdf = new KdfContext(api, Kdf.HkdfSha512, suiteId);
    const prim = new Ec(Kem.DhkemP521HkdfSha512, kdf, api);
    super(api, prim, kdf);
  }
}

export class DhkemX25519HkdfSha256 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemX25519HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 32;
  public readonly publicKeySize: number = 32;
  public readonly privateKeySize: number = 32;

  constructor(api: SubtleCrypto) {
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(Kem.DhkemX25519HkdfSha256, 2), 3);
    const kdf = new KdfContext(api, Kdf.HkdfSha256, suiteId);
    const prim = new X25519(kdf);
    super(api, prim, kdf);
  }
}

export class DhkemX448HkdfSha512 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemX448HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 56;
  public readonly publicKeySize: number = 56;
  public readonly privateKeySize: number = 56;

  constructor(api: SubtleCrypto) {
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(Kem.DhkemX448HkdfSha512, 2), 3);
    const kdf = new KdfContext(api, Kdf.HkdfSha512, suiteId);
    const prim = new X448(kdf);
    super(api, prim, kdf);
  }
}
