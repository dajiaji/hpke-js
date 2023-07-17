import type { KdfInterface } from "../interfaces/kdfInterface.ts";
import type { KemInterface } from "../interfaces/kemInterface.ts";
import type { KemPrimitives } from "../interfaces/kemPrimitives.ts";
import type { SenderContextParams } from "../interfaces/senderContextParams.ts";
import type { RecipientContextParams } from "../interfaces/recipientContextParams.ts";

import { Algorithm } from "../algorithm.ts";
import { Ec } from "./dhkemPrimitives/ec.ts";
import { Secp256K1 } from "./dhkemPrimitives/secp256k1.ts";
import { X25519 } from "./dhkemPrimitives/x25519.ts";
import { X448 } from "./dhkemPrimitives/x448.ts";
import { Kem } from "../identifiers.ts";
import { HkdfSha256, HkdfSha384, HkdfSha512 } from "../kdfs/hkdf.ts";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "../utils/misc.ts";

import * as consts from "../consts.ts";
import * as errors from "../errors.ts";

export class Dhkem extends Algorithm implements KemInterface {
  public readonly id: Kem = Kem.DhkemP256HkdfSha256;
  public readonly secretSize: number = 0;
  public readonly encSize: number = 0;
  public readonly publicKeySize: number = 0;
  public readonly privateKeySize: number = 0;
  protected _prim: KemPrimitives;
  protected _kdf: KdfInterface;

  constructor(prim: KemPrimitives, kdf: KdfInterface) {
    super();
    this._prim = prim;
    this._kdf = kdf;
  }

  public init(api: SubtleCrypto): void {
    super.init(api);
    const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
    suiteId.set(i2Osp(this.id, 2), 3);
    this._prim.init(api);
    this._kdf.init(api, suiteId);
    super.init(api);
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
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
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

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new Ec(Kem.DhkemP256HkdfSha256, kdf);
    super(prim, kdf);
  }
}

export class DhkemP384HkdfSha384 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemP384HkdfSha384;
  public readonly secretSize: number = 48;
  public readonly encSize: number = 97;
  public readonly publicKeySize: number = 97;
  public readonly privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384();
    const prim = new Ec(Kem.DhkemP384HkdfSha384, kdf);
    super(prim, kdf);
  }
}

export class DhkemP521HkdfSha512 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemP521HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 133;
  public readonly publicKeySize: number = 133;
  public readonly privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512();
    const prim = new Ec(Kem.DhkemP521HkdfSha512, kdf);
    super(prim, kdf);
  }
}

export class DhkemSecp256K1HkdfSha256 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemSecp256K1HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 65;
  public readonly publicKeySize: number = 65;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new Secp256K1(kdf);
    super(prim, kdf);
  }
}

export class DhkemX25519HkdfSha256 extends Dhkem {
  public readonly id: Kem = Kem.DhkemX25519HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 32;
  public readonly publicKeySize: number = 32;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new X25519(kdf);
    super(prim, kdf);
  }
}

export class DhkemX448HkdfSha512 extends Dhkem implements KemInterface {
  public readonly id: Kem = Kem.DhkemX448HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 56;
  public readonly publicKeySize: number = 56;
  public readonly privateKeySize: number = 56;

  constructor() {
    const kdf = new HkdfSha512();
    const prim = new X448(kdf);
    super(prim, kdf);
  }
}
