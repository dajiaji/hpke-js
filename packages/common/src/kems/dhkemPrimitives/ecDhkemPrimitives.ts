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
import { KEM_USAGES, LABEL_DKP_PRK } from "../../interfaces/dhkemPrimitives.ts";
import { base64UrlToBytes, i2Osp } from "../../utils/misc.ts";

// b"candidate"
// deno-fmt-ignore
const LABEL_CANDIDATE = /* @__PURE__ */ new Uint8Array([
  99, 97, 110, 100, 105, 100, 97, 116, 101,
]);

/**
 * Curve-specific parameters for {@link EcDhkemPrimitives}.
 *
 * Pass one of {@link EC_P_256}, {@link EC_P_384} or {@link EC_P_521} to the
 * {@link EcDhkemPrimitives} constructor. Keeping them as separate constants (instead of
 * selecting them by KEM ID as the deprecated `Ec` does) lets bundlers drop the parameters of
 * the curves that are not used.
 */
export interface EcCurve {
  /** The WebCrypto named curve. */
  readonly namedCurve: "P-256" | "P-384" | "P-521";
  /** The byte length of a scalar / field element (Nsk = Ndh). */
  readonly size: number;
  /** The bitmask applied to the first byte of a DeriveKeyPair candidate. */
  readonly bitmask: number;
  /** The PKCS#8 header preceding a raw private key of `size` bytes. */
  readonly pkcs8AlgId: Uint8Array;
  /** The order of the base point. */
  readonly n: bigint;
}

/** The curve parameters of P-256 for {@link EcDhkemPrimitives}. */
export const EC_P_256: EcCurve = {
  namedCurve: "P-256",
  size: 32,
  bitmask: 0xff,
  // deno-fmt-ignore
  pkcs8AlgId: /* @__PURE__ */ new Uint8Array([
    48, 65, 2, 1, 0, 48, 19, 6, 7, 42,
    134, 72, 206, 61, 2, 1, 6, 8, 42, 134,
    72, 206, 61, 3, 1, 7, 4, 39, 48, 37,
    2, 1, 1, 4, 32,
  ]),
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
};

/** The curve parameters of P-384 for {@link EcDhkemPrimitives}. */
export const EC_P_384: EcCurve = {
  namedCurve: "P-384",
  size: 48,
  bitmask: 0xff,
  // deno-fmt-ignore
  pkcs8AlgId: /* @__PURE__ */ new Uint8Array([
    48, 78, 2, 1, 0, 48, 16, 6, 7, 42,
    134, 72, 206, 61, 2, 1, 6, 5, 43, 129,
    4, 0, 34, 4, 55, 48, 53, 2, 1, 1,
    4, 48,
  ]),
  n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
};

/** The curve parameters of P-521 for {@link EcDhkemPrimitives}. */
export const EC_P_521: EcCurve = {
  namedCurve: "P-521",
  size: 66,
  bitmask: 0x01,
  // deno-fmt-ignore
  pkcs8AlgId: /* @__PURE__ */ new Uint8Array([
    48, 96, 2, 1, 0, 48, 16, 6, 7, 42,
    134, 72, 206, 61, 2, 1, 6, 5, 43, 129,
    4, 0, 35, 4, 73, 48, 71, 2, 1, 1,
    4, 66,
  ]),
  n: 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
};

function bigIntToBytes(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let n = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) {
    throw new Error("Invalid coordinate length");
  }
  return out;
}

// Compares two big-endian byte strings of the same length. Used instead of
// bigint for secret values so that they can be zeroized after use.
function lessThan(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i];
    }
  }
  return false;
}

function isZero(a: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < a.length; i++) {
    acc |= a[i];
  }
  return acc === 0;
}

export class EcDhkemPrimitives extends NativeAlgorithm
  implements DhkemPrimitives {
  private _hkdf: KdfInterface;
  private _curve: EcCurve;
  private _alg: EcKeyGenParams;
  private _nPk: number;
  private _nSk: number;

  /**
   * @param curve The curve parameters ({@link EC_P_256}, {@link EC_P_384} or {@link EC_P_521}).
   * @param hkdf The KDF used for DeriveKeyPair.
   */
  constructor(curve: EcCurve, hkdf: KdfInterface) {
    super();
    this._hkdf = hkdf;
    this._curve = curve;
    this._alg = { name: "ECDH", namedCurve: curve.namedCurve };
    this._nPk = 1 + curve.size * 2;
    this._nSk = curve.size;
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
        this._alg,
        true,
        KEM_USAGES,
      );
    } catch (e: unknown) {
      throw new NotSupportedError(e);
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
      const order = bigIntToBytes(this._curve.n, this._nSk);
      let sk: CryptoKey | undefined;
      for (let counter = 0; sk === undefined; counter++) {
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
        bytes[0] = bytes[0] & this._curve.bitmask;
        if (!isZero(bytes) && lessThan(bytes, order)) {
          sk = await this._deserializePkcs8Key(bytes);
        }
        bytes.fill(0);
      }
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
    const api = this._api as SubtleCrypto;
    try {
      let jwk: JsonWebKey;
      try {
        jwk = await api.exportKey("jwk", key);
      } catch {
        // Firefox cannot export a JWK from an ECDH private key imported from
        // a PKCS#8 without the public key (Mozilla bug 2000795), but its
        // PKCS#8 re-export includes the public key and can be re-imported.
        jwk = await api.exportKey(
          "jwk",
          await api.importKey(
            "pkcs8",
            await api.exportKey("pkcs8", key),
            this._alg,
            true,
            KEM_USAGES,
          ),
        );
      }
      delete jwk["d"];
      delete jwk["key_ops"];
      return await api.importKey("jwk", jwk, this._alg, true, []);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    try {
      await this._setup();
      const bits = await (this._api as SubtleCrypto).deriveBits(
        {
          name: "ECDH",
          public: pk,
        },
        sk,
        this._nSk * 8,
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

  private async _deserializePkcs8Key(k: Uint8Array): Promise<CryptoKey> {
    const algId = this._curve.pkcs8AlgId;
    const pkcs8Key = new Uint8Array(algId.length + k.length);
    pkcs8Key.set(algId, 0);
    pkcs8Key.set(k, algId.length);
    try {
      return await (this._api as SubtleCrypto).importKey(
        "pkcs8",
        pkcs8Key,
        this._alg,
        true,
        KEM_USAGES,
      );
    } finally {
      pkcs8Key.fill(0);
    }
  }
}
