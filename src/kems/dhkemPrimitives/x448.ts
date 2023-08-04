// @ts-ignore: for "npm:"
import { ed448, x448 } from "npm:@noble/curves@1.1.0/ed448";

import type { KemPrimitives } from "../../interfaces/kemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { Algorithm } from "../../algorithm.ts";
import { XCryptoKey } from "../../xCryptoKey.ts";

import * as consts from "../../consts.ts";
import { base64UrlToBytes } from "../../utils/misc.ts";

const ALG_NAME = "X448";

export class X448 extends Algorithm implements KemPrimitives {
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfInterface) {
    super();
    this._hkdf = hkdf;
    this._nPk = 56;
    this._nSk = 56;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this._serializePublicKey(key as XCryptoKey);
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._deserializePublicKey(key);
  }

  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    if (format === "raw") {
      return await this._importRawKey(key as ArrayBuffer, isPublic);
    }
    // jwk
    if (key instanceof ArrayBuffer) {
      throw new Error("Invalid jwk key format");
    }
    return await this._importJWK(key as JsonWebKey, isPublic);
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    return await this._derivePublicKey(key as XCryptoKey);
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    const rawSk = ed448.utils.randomPrivateKey();
    const sk = new XCryptoKey(ALG_NAME, rawSk, "private");
    const pk = await this.derivePublicKey(sk);
    return { publicKey: pk, privateKey: sk };
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    const dkpPrk = await this._hkdf.labeledExtract(
      consts.EMPTY,
      consts.LABEL_DKP_PRK,
      new Uint8Array(ikm),
    );
    const rawSk = await this._hkdf.labeledExpand(
      dkpPrk,
      consts.LABEL_SK,
      consts.EMPTY,
      this._nSk,
    );
    const sk = new XCryptoKey(ALG_NAME, new Uint8Array(rawSk), "private");
    return {
      privateKey: sk,
      publicKey: await this.derivePublicKey(sk),
    };
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    return await this._dh(sk as XCryptoKey, pk as XCryptoKey);
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      resolve(k.key.buffer);
    });
  }

  private _deserializePublicKey(k: ArrayBuffer): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (k.byteLength !== this._nPk) {
        reject(new Error("Invalid public key for the ciphersuite"));
      } else {
        resolve(new XCryptoKey(ALG_NAME, new Uint8Array(k), "public"));
      }
    });
  }

  private _importRawKey(
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (isPublic && key.byteLength !== this._nPk) {
        reject(new Error("Invalid public key for the ciphersuite"));
      }
      if (!isPublic && key.byteLength !== this._nSk) {
        reject(new Error("Invalid private key for the ciphersuite"));
      }
      resolve(
        new XCryptoKey(
          ALG_NAME,
          new Uint8Array(key),
          isPublic ? "public" : "private",
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
          ),
        );
      }
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve) => {
      const pk = x448.getPublicKey(k.key);
      resolve(new XCryptoKey(ALG_NAME, pk, "public"));
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
