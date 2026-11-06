import type { DhkemPrimitives } from "../../interfaces/dhkemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { NativeAlgorithm } from "../../algorithm.ts";
import { EMPTY } from "../../consts.ts";
import { mod } from "../../curve/modular.ts";
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
  /** The field prime. */
  readonly p: bigint;
  /** The curve coefficient b (a = -3). */
  readonly b: bigint;
  /** The x-coordinate of the base point. */
  readonly gx: bigint;
  /** The y-coordinate of the base point. */
  readonly gy: bigint;
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
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
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
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
  b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
  gx:
    0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
  gy:
    0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
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
  p: 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn,
  b: 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00n,
  gx:
    0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66n,
  gy:
    0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650n,
};

function modPow(base: bigint, exponent: bigint, p: bigint): bigint {
  let result = 1n;
  let b = mod(base, p);
  let e = exponent;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % p;
    }
    b = (b * b) % p;
    e >>= 1n;
  }
  return result;
}

function modSqrt(rhs: bigint, p: bigint): bigint {
  // P-256/P-384/P-521 primes satisfy p % 4 == 3.
  const y = modPow(rhs, (p + 1n) >> 2n, p);
  if ((y * y) % p !== rhs) {
    throw new Error("Invalid ECDH point");
  }
  return y;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) {
    v = (v << 8n) | BigInt(b);
  }
  return v;
}

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

function buildRawUncompressedPublicKey(
  x: bigint,
  y: bigint,
  size: number,
): Uint8Array {
  const out = new Uint8Array(1 + size * 2);
  out[0] = 0x04;
  out.set(bigIntToBytes(x, size), 1);
  out.set(bigIntToBytes(y, size), 1 + size);
  return out;
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
        // Firefox fails to export JWK from some imported ECDH private keys.
        return await this._derivePublicKeyWithoutJwkExport(key);
      } catch (e: unknown) {
        throw new DeserializeError(e);
      }
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

  private async _derivePublicKeyWithoutJwkExport(
    key: CryptoKey,
  ): Promise<CryptoKey> {
    const { p, b, gx, gy, size } = this._curve;
    const basePointRaw = buildRawUncompressedPublicKey(gx, gy, size);
    const basePoint = await (this._api as SubtleCrypto).importKey(
      "raw",
      basePointRaw.buffer as ArrayBuffer,
      this._alg,
      true,
      [],
    );
    const xBytes = new Uint8Array(
      await (this._api as SubtleCrypto).deriveBits(
        {
          name: "ECDH",
          public: basePoint,
        },
        key,
        this._nSk * 8,
      ),
    );
    const x = bytesToBigInt(xBytes);
    const rhs = mod(x * x * x - 3n * x + b, p);
    let y = modSqrt(rhs, p);
    // Canonicalize sign so the encoded point is deterministic.
    if ((y & 1n) === 1n) {
      y = p - y;
    }
    const pubRaw = buildRawUncompressedPublicKey(x, y, size);
    return await (this._api as SubtleCrypto).importKey(
      "raw",
      pubRaw.buffer as ArrayBuffer,
      this._alg,
      true,
      [],
    );
  }
}
