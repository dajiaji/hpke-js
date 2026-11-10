import type { DhkemPrimitives } from "../../interfaces/dhkemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { NativeAlgorithm } from "../../algorithm.ts";
import { EMPTY } from "../../consts.ts";
import { toArrayBuffer } from "../../kdfs/hkdf.ts";
import {
  DeriveKeyPairError,
  DeserializeError,
  NotSupportedError,
  SerializeError,
} from "../../errors.ts";
import {
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
} from "../../interfaces/dhkemPrimitives.ts";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  loadCrypto,
} from "../../utils/misc.ts";

/**
 * Curve-specific parameters for {@link XCurveNativeDhkemPrimitives}.
 *
 * Pass {@link X_CURVE_X25519} or {@link X_CURVE_X448} to the
 * {@link XCurveNativeDhkemPrimitives} constructor. Keeping them as separate constants lets
 * bundlers drop the parameters of the curve that is not used.
 */
export interface XCurve {
  /** The WebCrypto algorithm name. */
  readonly name: "X25519" | "X448";
  /** The byte length of a public key, private key and shared secret (Npk = Nsk = Ndh). */
  readonly size: number;
  /** The PKCS#8 header preceding a raw private key of `size` bytes. */
  readonly pkcs8AlgId: Uint8Array;
  /** The encoded base point u-coordinate. */
  readonly basePoint: Uint8Array;
}

/** X25519 parameters for {@link XCurveNativeDhkemPrimitives}. */
export const X_CURVE_X25519: XCurve = {
  name: "X25519",
  size: 32,
  // deno-fmt-ignore
  pkcs8AlgId: /* @__PURE__ */ new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]),
  basePoint: /* @__PURE__ */ (() => {
    const p = new Uint8Array(32);
    p[0] = 9;
    return p;
  })(),
};

/** X448 parameters for {@link XCurveNativeDhkemPrimitives}. */
export const X_CURVE_X448: XCurve = {
  name: "X448",
  size: 56,
  // deno-fmt-ignore
  pkcs8AlgId: /* @__PURE__ */ new Uint8Array([
    0x30, 0x46, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6f, 0x04, 0x3a, 0x04, 0x38,
  ]),
  basePoint: /* @__PURE__ */ (() => {
    const p = new Uint8Array(56);
    p[0] = 5;
    return p;
  })(),
};

/**
 * DHKEM primitives for X25519 / X448 backed by the WebCrypto API.
 */
export class XCurveNativeDhkemPrimitives extends NativeAlgorithm
  implements DhkemPrimitives {
  private _hkdf: KdfInterface;
  private _alg: KeyAlgorithm;
  private _nPk: number;
  private _nSk: number;
  private _nDh: number;
  private _pkcs8AlgId: Uint8Array;
  private _algName: string;
  private _basePoint: Uint8Array;

  /**
   * @param curve The curve parameters ({@link X_CURVE_X25519} or {@link X_CURVE_X448}).
   * @param hkdf The KDF used for DeriveKeyPair.
   */
  constructor(curve: XCurve, hkdf: KdfInterface) {
    super();
    this._algName = curve.name;
    this._alg = { name: curve.name };
    this._hkdf = hkdf;
    this._nPk = curve.size;
    this._nSk = curve.size;
    this._nDh = curve.size;
    this._pkcs8AlgId = curve.pkcs8AlgId;
    this._basePoint = curve.basePoint;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      return await (this._api as SubtleCrypto).exportKey("raw", key);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._importRawKey(toArrayBuffer(key), true);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      const jwk = await (this._api as SubtleCrypto).exportKey("jwk", key);
      if (!("d" in jwk)) {
        throw new Error("Not private key");
      }
      return base64UrlToBytes(jwk["d"] as string).buffer as ArrayBuffer;
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePrivateKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    await this._setup();
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
    await this._setup();
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
    await this._setup();
    try {
      return await (this._api as SubtleCrypto).generateKey(
        this._algName,
        true,
        KEM_USAGES,
      ) as CryptoKeyPair;
    } catch (e: unknown) {
      // WebKit fails to generate a key pair whose private key would start
      // with 0x00 (about 1 in 256 attempts), so fall back to importing a
      // random private key. If the curve itself is not supported, this
      // fails as well and the original error is reported.
      try {
        return await this._generateKeyPairFromRandomBytes();
      } catch {
        throw new NotSupportedError(e);
      }
    }
  }

  public async deriveKeyPair(
    ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKeyPair> {
    await this._setup();
    try {
      const rawIkm = toArrayBuffer(ikm);
      const dkpPrk = await this._hkdf.labeledExtract(
        EMPTY,
        LABEL_DKP_PRK,
        new Uint8Array(rawIkm),
      );
      const rawSk = await this._hkdf.labeledExpand(
        dkpPrk,
        LABEL_SK,
        EMPTY,
        this._nSk,
      );
      const rawSkBytes = new Uint8Array(rawSk);
      const sk = await this._deserializePkcs8Key(rawSkBytes);
      rawSkBytes.fill(0);
      return {
        privateKey: sk,
        publicKey: await this.derivePublicKey(sk),
      };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    await this._setup();
    try {
      const jwk = await (this._api as SubtleCrypto).exportKey("jwk", key);
      delete jwk["d"];
      delete jwk["key_ops"];
      return await (this._api as SubtleCrypto).importKey(
        "jwk",
        jwk,
        this._alg,
        true,
        [],
      );
    } catch {
      try {
        const bp = await (this._api as SubtleCrypto).importKey(
          "raw",
          this._basePoint.buffer as ArrayBuffer,
          this._alg,
          true,
          [],
        );
        const bits = await (this._api as SubtleCrypto).deriveBits(
          {
            name: this._algName,
            public: bp,
          },
          key,
          this._nPk * 8,
        );
        return await (this._api as SubtleCrypto).importKey(
          "raw",
          bits,
          this._alg,
          true,
          [],
        );
      } catch (e: unknown) {
        throw new DeserializeError(e);
      }
    }
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      const bits = await (this._api as SubtleCrypto).deriveBits(
        {
          name: this._algName,
          public: pk,
        },
        sk,
        this._nDh * 8,
      );
      return bits;
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
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
    if (isPublic) {
      return await (this._api as SubtleCrypto).importKey(
        "raw",
        key,
        this._alg,
        true,
        [],
      );
    }
    return await this._deserializePkcs8Key(new Uint8Array(key));
  }

  private async _importJWK(
    key: JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    if (typeof key.kty === "undefined" || key.kty !== "OKP") {
      throw new Error(`Invalid kty: ${key.crv}`);
    }
    if (typeof key.crv === "undefined" || key.crv !== this._algName) {
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

  private async _generateKeyPairFromRandomBytes(): Promise<CryptoKeyPair> {
    const sk = new Uint8Array(this._nSk);
    try {
      (await loadCrypto()).getRandomValues(sk);
      const privateKey = await this._deserializePkcs8Key(sk);
      return {
        privateKey,
        publicKey: await this.derivePublicKey(privateKey),
      };
    } finally {
      sk.fill(0);
    }
  }

  private async _deserializePkcs8Key(k: Uint8Array): Promise<CryptoKey> {
    const pkcs8Key = this._toPkcs8(k);
    try {
      return await (this._api as SubtleCrypto).importKey(
        "pkcs8",
        pkcs8Key,
        this._alg,
        true,
        KEM_USAGES,
      );
    } catch (e: unknown) {
      if (k[0] !== 0) {
        throw e;
      }
      // WebKit rejects a PKCS#8 private key whose first byte is 0x00.
      return await this._importLeadingZeroKey(k);
    } finally {
      pkcs8Key.fill(0);
    }
  }

  // Imports a private key whose first byte is 0x00 as a JWK, which WebKit
  // accepts. The public key (`x`) required for the JWK is computed from the
  // same key with the first byte set to 0x01: decoding the scalar clears the
  // low bits of the first byte (RFC 7748), so both have the same scalar and
  // therefore the same public key.
  private async _importLeadingZeroKey(k: Uint8Array): Promise<CryptoKey> {
    const api = this._api as SubtleCrypto;
    const alt = this._toPkcs8(k);
    alt[this._pkcs8AlgId.length] = 0x01;
    try {
      const altKey = await api.importKey(
        "pkcs8",
        alt,
        this._alg,
        true,
        KEM_USAGES,
      );
      const { x } = await api.exportKey("jwk", altKey);
      return await api.importKey(
        "jwk",
        { kty: "OKP", crv: this._algName, x, d: bytesToBase64Url(k) },
        this._alg,
        true,
        KEM_USAGES,
      );
    } finally {
      alt.fill(0);
    }
  }

  private _toPkcs8(k: Uint8Array) {
    const pkcs8Key = new Uint8Array(this._pkcs8AlgId.length + k.length);
    pkcs8Key.set(this._pkcs8AlgId, 0);
    pkcs8Key.set(k, this._pkcs8AlgId.length);
    return pkcs8Key;
  }
}
