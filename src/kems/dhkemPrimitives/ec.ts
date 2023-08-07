import type { KemPrimitives } from "../../interfaces/kemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { Algorithm } from "../../algorithm.ts";
import { KemId } from "../../identifiers.ts";
import { KEM_USAGES, LABEL_DKP_PRK } from "../../interfaces/kemPrimitives.ts";
import { Bignum } from "../../utils/bignum.ts";
import { i2Osp } from "../../utils/misc.ts";

import { EMPTY } from "../../consts.ts";

// b"candidate"
const LABEL_CANDIDATE = new Uint8Array([
  99,
  97,
  110,
  100,
  105,
  100,
  97,
  116,
  101,
]);

// the order of the curve being used.
const ORDER_P_256 = new Uint8Array([
  0xff,
  0xff,
  0xff,
  0xff,
  0x00,
  0x00,
  0x00,
  0x00,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xbc,
  0xe6,
  0xfa,
  0xad,
  0xa7,
  0x17,
  0x9e,
  0x84,
  0xf3,
  0xb9,
  0xca,
  0xc2,
  0xfc,
  0x63,
  0x25,
  0x51,
]);

const ORDER_P_384 = new Uint8Array([
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xc7,
  0x63,
  0x4d,
  0x81,
  0xf4,
  0x37,
  0x2d,
  0xdf,
  0x58,
  0x1a,
  0x0d,
  0xb2,
  0x48,
  0xb0,
  0xa7,
  0x7a,
  0xec,
  0xec,
  0x19,
  0x6a,
  0xcc,
  0xc5,
  0x29,
  0x73,
]);

const ORDER_P_521 = new Uint8Array([
  0x01,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xff,
  0xfa,
  0x51,
  0x86,
  0x87,
  0x83,
  0xbf,
  0x2f,
  0x96,
  0x6b,
  0x7f,
  0xcc,
  0x01,
  0x48,
  0xf7,
  0x09,
  0xa5,
  0xd0,
  0x3b,
  0xb5,
  0xc9,
  0xb8,
  0x89,
  0x9c,
  0x47,
  0xae,
  0xbb,
  0x6f,
  0xb7,
  0x1e,
  0x91,
  0x38,
  0x64,
  0x09,
]);

const PKCS8_ALG_ID_P_256 = new Uint8Array([
  48,
  65,
  2,
  1,
  0,
  48,
  19,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  8,
  42,
  134,
  72,
  206,
  61,
  3,
  1,
  7,
  4,
  39,
  48,
  37,
  2,
  1,
  1,
  4,
  32,
]);

const PKCS8_ALG_ID_P_384 = new Uint8Array([
  48,
  78,
  2,
  1,
  0,
  48,
  16,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  5,
  43,
  129,
  4,
  0,
  34,
  4,
  55,
  48,
  53,
  2,
  1,
  1,
  4,
  48,
]);

const PKCS8_ALG_ID_P_521 = new Uint8Array([
  48,
  96,
  2,
  1,
  0,
  48,
  16,
  6,
  7,
  42,
  134,
  72,
  206,
  61,
  2,
  1,
  6,
  5,
  43,
  129,
  4,
  0,
  35,
  4,
  73,
  48,
  71,
  2,
  1,
  1,
  4,
  66,
]);

export class Ec extends Algorithm implements KemPrimitives {
  private _hkdf: KdfInterface;
  private _alg: EcKeyGenParams;
  private _nPk: number;
  private _nSk: number;
  private _nDh: number;

  // EC specific arguments for deriving key pair.
  private _order: Uint8Array;
  private _bitmask: number;
  private _pkcs8AlgId: Uint8Array;

  constructor(kem: KemId, hkdf: KdfInterface) {
    super();
    this._hkdf = hkdf;
    switch (kem) {
      case KemId.DhkemP256HkdfSha256:
        this._alg = { name: "ECDH", namedCurve: "P-256" };
        this._nPk = 65;
        this._nSk = 32;
        this._nDh = 32;
        this._order = ORDER_P_256;
        this._bitmask = 0xFF;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_256;
        break;
      case KemId.DhkemP384HkdfSha384:
        this._alg = { name: "ECDH", namedCurve: "P-384" };
        this._nPk = 97;
        this._nSk = 48;
        this._nDh = 48;
        this._order = ORDER_P_384;
        this._bitmask = 0xFF;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_384;
        break;
      default:
        // case KemId.DhkemP521HkdfSha512:
        this._alg = { name: "ECDH", namedCurve: "P-521" };
        this._nPk = 133;
        this._nSk = 66;
        this._nDh = 66;
        this._order = ORDER_P_521;
        this._bitmask = 0x01;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_521;
        break;
    }
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    this.checkInit();
    const ret = await (this._api as SubtleCrypto).exportKey("raw", key);
    // const ret = (await this._api.exportKey('spki', key)).slice(24);
    if (ret.byteLength !== this._nPk) {
      throw new Error("Invalid public key for the ciphersuite");
    }
    return ret;
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    this.checkInit();
    if (key.byteLength !== this._nPk) {
      throw new Error("Invalid public key for the ciphersuite");
    }
    try {
      return await (this._api as SubtleCrypto).importKey(
        "raw",
        key,
        this._alg,
        true,
        [],
      );
    } catch (_e: unknown) {
      throw new Error("Invalid public key for the ciphersuite");
    }
  }

  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    this.checkInit();
    if (format === "raw") {
      return await this._importRawKey(key as ArrayBuffer, isPublic);
    }
    // jwk
    if (key instanceof ArrayBuffer) {
      throw new Error("Invalid jwk key format");
    }
    return await this._importJWK(key as JsonWebKey, isPublic);
  }

  private async _importRawKey(
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    if (isPublic && key.byteLength !== this._nPk) {
      throw new Error("Invalid public key for the ciphersuite");
    }
    if (!isPublic && key.byteLength !== this._nSk) {
      throw new Error("Invalid private key for the ciphersuite");
    }
    try {
      if (isPublic) {
        return await (this._api as SubtleCrypto).importKey(
          "raw",
          key,
          this._alg,
          true,
          [],
        );
      }
      const k = new Uint8Array(key);
      const pkcs8Key = new Uint8Array(this._pkcs8AlgId.length + k.length);
      pkcs8Key.set(this._pkcs8AlgId, 0);
      pkcs8Key.set(k, this._pkcs8AlgId.length);
      return await (this._api as SubtleCrypto).importKey(
        "pkcs8",
        pkcs8Key,
        this._alg,
        true,
        KEM_USAGES,
      );
    } catch (_e: unknown) {
      throw new Error("Invalid key for the ciphersuite");
    }
  }

  private async _importJWK(
    key: JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    if (typeof key.crv === "undefined" || key.crv !== this._alg.namedCurve) {
      throw new Error(`Invalid crv: ${key.crv}`);
    }
    if (isPublic) {
      if (typeof key.d !== "undefined") {
        throw new Error("Invalid key: `d` should not be set");
      }
      return await (this._api as SubtleCrypto).importKey(
        "jwk",
        key,
        this._alg,
        true,
        [],
      );
    }
    if (typeof key.d === "undefined") {
      throw new Error("Invalid key: `d` not found");
    }
    return await (this._api as SubtleCrypto).importKey(
      "jwk",
      key,
      this._alg,
      true,
      KEM_USAGES,
    );
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    this.checkInit();
    const jwk = await (this._api as SubtleCrypto).exportKey("jwk", key);
    delete jwk["d"];
    delete jwk["key_ops"];
    // return await this._api.importKey('jwk', jwk, this._alg, true, KEM_USAGES);
    return await (this._api as SubtleCrypto).importKey(
      "jwk",
      jwk,
      this._alg,
      true,
      [],
    );
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    this.checkInit();
    return await (this._api as SubtleCrypto).generateKey(
      this._alg,
      true,
      KEM_USAGES,
    );
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    this.checkInit();
    const dkpPrk = await this._hkdf.labeledExtract(
      EMPTY,
      LABEL_DKP_PRK,
      new Uint8Array(ikm),
    );
    const bn = new Bignum(this._nSk);
    for (let counter = 0; bn.isZero() || !bn.lessThan(this._order); counter++) {
      if (counter > 255) {
        throw new Error("Faild to derive a key pair");
      }
      const bytes = new Uint8Array(
        await this._hkdf.labeledExpand(
          dkpPrk,
          LABEL_CANDIDATE,
          i2Osp(counter, 1),
          this._nSk,
        ),
      );
      bytes[0] = bytes[0] & this._bitmask;
      bn.set(bytes);
    }
    const pkcs8Key = new Uint8Array(this._pkcs8AlgId.length + bn.val().length);
    pkcs8Key.set(this._pkcs8AlgId, 0);
    pkcs8Key.set(bn.val(), this._pkcs8AlgId.length);
    const sk = await (this._api as SubtleCrypto).importKey(
      "pkcs8",
      pkcs8Key,
      this._alg,
      true,
      KEM_USAGES,
    );
    bn.reset();
    return {
      privateKey: sk,
      publicKey: await this.derivePublicKey(sk),
    };
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    this.checkInit();
    const bits = await (this._api as SubtleCrypto).deriveBits(
      {
        name: "ECDH",
        public: pk,
      },
      sk,
      this._nDh * 8,
    );
    return bits;
  }
}
