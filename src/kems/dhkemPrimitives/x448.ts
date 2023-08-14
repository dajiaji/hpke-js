// @ts-ignore: for "npm:"
import { ed448, x448 } from "npm:@noble/curves@1.1.0/ed448";

import type { KemPrimitives } from "../../interfaces/kemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import * as consts from "../../consts.ts";
import * as errors from "../../errors.ts";
import {
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
} from "../../interfaces/kemPrimitives.ts";
import { base64UrlToBytes } from "../../utils/misc.ts";
import { XCryptoKey } from "../../xCryptoKey.ts";

const ALG_NAME = "X448";

export class X448 implements KemPrimitives {
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfInterface) {
    this._hkdf = hkdf;
    this._nPk = 56;
    this._nSk = 56;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new errors.SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._importRawKey(key, true);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePrivateKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new errors.SerializeError(e);
    }
  }

  public async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._importRawKey(key, false);
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
      if (format === "raw") {
        return await this._importRawKey(key as ArrayBuffer, isPublic);
      }
      // jwk
      if (key instanceof ArrayBuffer) {
        throw new Error("Invalid jwk key format");
      }
      return await this._importJWK(key as JsonWebKey, isPublic);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    try {
      return await this._derivePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new errors.DeserializeError(e);
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      const rawSk = ed448.utils.randomPrivateKey();
      const sk = new XCryptoKey(ALG_NAME, rawSk, "private", KEM_USAGES);
      const pk = await this.derivePublicKey(sk);
      return { publicKey: pk, privateKey: sk };
    } catch (e: unknown) {
      throw new errors.NotSupportedError(e);
    }
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    try {
      const dkpPrk = await this._hkdf.labeledExtract(
        consts.EMPTY,
        LABEL_DKP_PRK,
        new Uint8Array(ikm),
      );
      const rawSk = await this._hkdf.labeledExpand(
        dkpPrk,
        LABEL_SK,
        consts.EMPTY,
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
      throw new errors.DeriveKeyPairError(e);
    }
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._dh(sk as XCryptoKey, pk as XCryptoKey);
    } catch (e: unknown) {
      throw new errors.SerializeError(e);
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
      if (
        !isPublic &&
        (key.byteLength !== this._nSk && key.byteLength !== this._nSk + 1)
      ) {
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

  private _importJWK(key: JsonWebKey, isPublic: boolean): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (key.kty !== "OKP") {
        reject(new Error(`Invalid kty: ${key.kty}`));
      }
      if (key.crv !== "X448") {
        reject(new Error(`Invalid crv: ${key.crv}`));
      }
      if (isPublic) {
        if (typeof key.d !== "undefined") {
          reject(new Error("Invalid key: `d` should not be set"));
        }
        if (typeof key.x !== "string") {
          reject(new Error("Invalid key: `x` not found"));
        }
        resolve(
          new XCryptoKey(
            ALG_NAME,
            base64UrlToBytes(key.x as string),
            "public",
          ),
        );
      } else {
        if (typeof key.d !== "string") {
          reject(new Error("Invalid key: `d` not found"));
        }
        resolve(
          new XCryptoKey(
            ALG_NAME,
            base64UrlToBytes(key.d as string),
            "private",
            KEM_USAGES,
          ),
        );
      }
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      try {
        const pk = x448.getPublicKey(k.key);
        resolve(new XCryptoKey(ALG_NAME, pk, "public"));
      } catch (e: unknown) {
        reject(e);
      }
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        resolve(x448.getSharedSecret(sk.key, pk.key).buffer);
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}
