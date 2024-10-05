import { secp256k1 } from "@noble/curves/secp256k1";

import type { DhkemPrimitives, KdfInterface } from "@hpke/common";

import {
  DeriveKeyPairError,
  DeserializeError,
  NotSupportedError,
  SerializeError,
  XCryptoKey,
} from "@hpke/core";

const ALG_NAME = "ECDH";
const EMPTY = new Uint8Array();
// The key usages for KEM.
const KEM_USAGES: KeyUsage[] = ["deriveBits"];
// b"dkp_prk" deno-fmt-ignore
const LABEL_DKP_PRK: Uint8Array = new Uint8Array([
  100, 107, 112, 95, 112, 114, 107,
]);
// b"sk"
const LABEL_SK: Uint8Array = new Uint8Array([115, 107]);

export class Secp256k1 implements DhkemPrimitives {
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfInterface) {
    this._hkdf = hkdf;
    this._nPk = 33;
    this._nSk = 32;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._importRawKey(key, true);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePrivateKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._importRawKey(key, false);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async importKey(
    format: "raw",
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    try {
      if (format !== "raw") {
        throw new Error("Unsupported format");
      }
      return await this._importRawKey(key, isPublic);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      const rawSk = secp256k1.utils.randomPrivateKey();
      const sk = new XCryptoKey(ALG_NAME, rawSk, "private", KEM_USAGES);
      const pk = await this.derivePublicKey(sk);
      return { publicKey: pk, privateKey: sk };
    } catch (e: unknown) {
      throw new NotSupportedError(e);
    }
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    try {
      const dkpPrk = await this._hkdf.labeledExtract(
        EMPTY,
        LABEL_DKP_PRK,
        new Uint8Array(ikm),
      );
      const rawSk = await this._hkdf.labeledExpand(
        dkpPrk,
        LABEL_SK,
        EMPTY,
        this._nSk,
      );
      const sk = new XCryptoKey(
        ALG_NAME,
        new Uint8Array(rawSk),
        "private",
        KEM_USAGES,
      );
      return {
        privateKey: sk,
        publicKey: await this.derivePublicKey(sk),
      };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    try {
      return await this._derivePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._dh(sk as XCryptoKey, pk as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      resolve(k.key.buffer);
    });
  }

  private _serializePrivateKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      resolve(k.key.buffer);
    });
  }

  private _importRawKey(
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (isPublic && key.byteLength !== this._nPk) {
        reject(new Error("Invalid length of the key"));
      }
      if (!isPublic && key.byteLength !== this._nSk) {
        reject(new Error("Invalid length of the key"));
      }
      resolve(
        new XCryptoKey(
          ALG_NAME,
          new Uint8Array(key),
          isPublic ? "public" : "private",
          isPublic ? [] : KEM_USAGES,
        ),
      );
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      try {
        const pk = secp256k1.getPublicKey(k.key);
        resolve(new XCryptoKey(ALG_NAME, pk, "public"));
      } catch (e: unknown) {
        reject(e);
      }
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        resolve(secp256k1.getSharedSecret(sk.key, pk.key).buffer);
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}
