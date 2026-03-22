import type { DhkemPrimitives } from "../../interfaces/dhkemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";
import type { MontgomeryECDH } from "../../curve/montgomery.ts";

import { EMPTY } from "../../consts.ts";
import {
  DeriveKeyPairError,
  DeserializeError,
  NotSupportedError,
  SerializeError,
} from "../../errors.ts";
import { toArrayBuffer } from "../../kdfs/hkdf.ts";
import {
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
} from "../../interfaces/dhkemPrimitives.ts";
import { base64UrlToBytes, loadCrypto } from "../../utils/misc.ts";
import { XCryptoKey } from "../../xCryptoKey.ts";

/**
 * Base DhkemPrimitives implementation for Montgomery curves (X25519/X448).
 *
 * Subclasses pass curve-specific parameters (algorithm name, key size, curve)
 * and optionally add extra methods (e.g., raw derive for X25519).
 */
export class XCurveDhkemPrimitives implements DhkemPrimitives {
  private _algName: string;
  protected _curve: MontgomeryECDH;
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(
    algName: string,
    keySize: number,
    curve: MontgomeryECDH,
    hkdf: KdfInterface,
  ) {
    this._algName = algName;
    this._nPk = keySize;
    this._nSk = keySize;
    this._curve = curve;
    this._hkdf = hkdf;
  }

  public serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return Promise.resolve((key as XCryptoKey).key.buffer as ArrayBuffer);
    } catch (e: unknown) {
      return Promise.reject(new SerializeError(e));
    }
  }

  public async deserializePublicKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    try {
      return await this._importRawKey(toArrayBuffer(key), true);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return Promise.resolve((key as XCryptoKey).key.buffer as ArrayBuffer);
    } catch (e: unknown) {
      return Promise.reject(new SerializeError(e));
    }
  }

  public async deserializePrivateKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    try {
      return await this._importRawKey(toArrayBuffer(key), false);
    } catch (e: unknown) {
      throw new DeserializeError(e);
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
      throw new DeserializeError(e);
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      let rawSk: Uint8Array;
      try {
        rawSk = this._curve.utils.randomSecretKey();
      } catch {
        // Sync crypto not available (e.g., Node.js <= v18 ESM); async fallback
        const cryptoApi = await loadCrypto();
        rawSk = new Uint8Array(this._nSk);
        cryptoApi.getRandomValues(rawSk);
      }
      const sk = new XCryptoKey(
        this._algName,
        rawSk,
        "private",
        KEM_USAGES,
      );
      const rawPk = this._curve.getPublicKey(rawSk);
      const pk = new XCryptoKey(this._algName, rawPk, "public") as CryptoKey;
      return { publicKey: pk, privateKey: sk };
    } catch (e: unknown) {
      throw new NotSupportedError(e);
    }
  }

  public async deriveKeyPair(
    ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKeyPair> {
    try {
      const rawIkm = toArrayBuffer(ikm);
      const dkpPrk = await this._hkdf.labeledExtract(
        EMPTY.buffer as ArrayBuffer,
        LABEL_DKP_PRK,
        new Uint8Array(rawIkm),
      );
      const rawSk = await this._hkdf.labeledExpand(
        dkpPrk,
        LABEL_SK,
        EMPTY,
        this._nSk,
      );
      const sk = new XCryptoKey(
        this._algName,
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

  public derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    try {
      const pk = this._curve.getPublicKey((key as XCryptoKey).key);
      return Promise.resolve(
        new XCryptoKey(this._algName, pk, "public") as CryptoKey,
      );
    } catch (e: unknown) {
      return Promise.reject(new DeserializeError(e));
    }
  }

  public dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    try {
      return Promise.resolve(
        this._curve.getSharedSecret(
          (sk as XCryptoKey).key,
          (pk as XCryptoKey).key,
        ).buffer as ArrayBuffer,
      );
    } catch (e: unknown) {
      return Promise.reject(new SerializeError(e));
    }
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
          this._algName,
          new Uint8Array(key),
          isPublic ? "public" : "private",
          isPublic ? [] : KEM_USAGES,
        ),
      );
    });
  }

  private _importJWK(
    key: JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (key.kty !== "OKP") {
        reject(new Error(`Invalid kty: ${key.kty}`));
      }
      if (key.crv !== this._algName) {
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
            this._algName,
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
            this._algName,
            base64UrlToBytes(key.d as string),
            "private",
            KEM_USAGES,
          ),
        );
      }
    });
  }
}
