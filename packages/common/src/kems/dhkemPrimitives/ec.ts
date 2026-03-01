import type { DhkemPrimitives } from "../../interfaces/dhkemPrimitives.ts";
import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { NativeAlgorithm } from "../../algorithm.ts";
import { EMPTY } from "../../consts.ts";
import {
  DeriveKeyPairError,
  DeserializeError,
  NotSupportedError,
  SerializeError,
} from "../../errors.ts";
import { KemId } from "../../identifiers.ts";
import { KEM_USAGES, LABEL_DKP_PRK } from "../../interfaces/dhkemPrimitives.ts";
import { Bignum } from "../../utils/bignum.ts";
import { base64UrlToBytes, i2Osp } from "../../utils/misc.ts";

// b"candidate"
// deno-fmt-ignore
const LABEL_CANDIDATE = /* @__PURE__ */ new Uint8Array([
  99, 97, 110, 100, 105, 100, 97, 116, 101,
]);

// the order of the curve being used.
// deno-fmt-ignore
const ORDER_P_256 = /* @__PURE__ */ new Uint8Array([
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
  0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
]);

// deno-fmt-ignore
const ORDER_P_384 = /* @__PURE__ */ new Uint8Array([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
  0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a,
  0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
]);

// deno-fmt-ignore
const ORDER_P_521 = /* @__PURE__ */ new Uint8Array([
  0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f,
  0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
  0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c,
  0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
  0x64, 0x09,
]);

// deno-fmt-ignore
const PKCS8_ALG_ID_P_256 = /* @__PURE__ */ new Uint8Array([
  48, 65, 2, 1, 0, 48, 19, 6, 7, 42,
  134, 72, 206, 61, 2, 1, 6, 8, 42, 134,
  72, 206, 61, 3, 1, 7, 4, 39, 48, 37,
  2, 1, 1, 4, 32,
]);

// deno-fmt-ignore
const PKCS8_ALG_ID_P_384 = /* @__PURE__ */ new Uint8Array([
  48, 78, 2, 1, 0, 48, 16, 6, 7, 42,
  134, 72, 206, 61, 2, 1, 6, 5, 43, 129,
  4, 0, 34, 4, 55, 48, 53, 2, 1, 1,
  4, 48,
]);

// deno-fmt-ignore
const PKCS8_ALG_ID_P_521 = /* @__PURE__ */ new Uint8Array([
  48, 96, 2, 1, 0, 48, 16, 6, 7, 42,
  134, 72, 206, 61, 2, 1, 6, 5, 43, 129,
  4, 0, 35, 4, 73, 48, 71, 2, 1, 1,
  4, 66,
]);

interface EcCurveParams {
  p: bigint;
  b: bigint;
  gx: bigint;
  gy: bigint;
  coordinateSize: number;
}

const EC_P_256_PARAMS: EcCurveParams = {
  p: BigInt(
    "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
  ),
  b: BigInt(
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
  ),
  gx: BigInt(
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
  ),
  gy: BigInt(
    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
  ),
  coordinateSize: 32,
};

const EC_P_384_PARAMS: EcCurveParams = {
  p: BigInt(
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
  ),
  b: BigInt(
    "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
  ),
  gx: BigInt(
    "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
  ),
  gy: BigInt(
    "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
  ),
  coordinateSize: 48,
};

const EC_P_521_PARAMS: EcCurveParams = {
  p: (BigInt(1) << BigInt(521)) - BigInt(1),
  b: BigInt(
    "0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
  ),
  gx: BigInt(
    "0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
  ),
  gy: BigInt(
    "0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
  ),
  coordinateSize: 66,
};

function mod(a: bigint, p: bigint): bigint {
  const r = a % p;
  return r >= BigInt(0) ? r : r + p;
}

function modPow(base: bigint, exponent: bigint, p: bigint): bigint {
  let result = BigInt(1);
  let b = mod(base, p);
  let e = exponent;
  while (e > BigInt(0)) {
    if ((e & BigInt(1)) === BigInt(1)) {
      result = mod(result * b, p);
    }
    b = mod(b * b, p);
    e >>= BigInt(1);
  }
  return result;
}

function modSqrt(rhs: bigint, p: bigint): bigint {
  // P-256/P-384/P-521 primes satisfy p % 4 == 3.
  const y = modPow(rhs, (p + BigInt(1)) >> BigInt(2), p);
  if (mod(y * y, p) !== mod(rhs, p)) {
    throw new Error("Invalid ECDH point");
  }
  return y;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = BigInt(0);
  for (const b of bytes) {
    v = (v << BigInt(8)) | BigInt(b);
  }
  return v;
}

function bigIntToBytes(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let n = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & BigInt(0xff));
    n >>= BigInt(8);
  }
  if (n !== BigInt(0)) {
    throw new Error("Invalid coordinate length");
  }
  return out;
}

function buildRawUncompressedPublicKey(
  x: bigint,
  y: bigint,
  coordinateSize: number,
): Uint8Array {
  const out = new Uint8Array(1 + coordinateSize * 2);
  out[0] = 0x04;
  out.set(bigIntToBytes(x, coordinateSize), 1);
  out.set(bigIntToBytes(y, coordinateSize), 1 + coordinateSize);
  return out;
}

export class Ec extends NativeAlgorithm implements DhkemPrimitives {
  private _hkdf: KdfInterface;
  private _alg: EcKeyGenParams;
  private _nPk: number;
  private _nSk: number;
  private _nDh: number;

  // EC specific arguments for deriving key pair.
  private _order: Uint8Array;
  private _bitmask: number;
  private _pkcs8AlgId: Uint8Array;
  private _curveParams: EcCurveParams;

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
        this._curveParams = EC_P_256_PARAMS;
        break;
      case KemId.DhkemP384HkdfSha384:
        this._alg = { name: "ECDH", namedCurve: "P-384" };
        this._nPk = 97;
        this._nSk = 48;
        this._nDh = 48;
        this._order = ORDER_P_384;
        this._bitmask = 0xFF;
        this._pkcs8AlgId = PKCS8_ALG_ID_P_384;
        this._curveParams = EC_P_384_PARAMS;
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
        this._curveParams = EC_P_521_PARAMS;
        break;
    }
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      return await (this._api as SubtleCrypto).exportKey("raw", key);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._importRawKey(key, true);
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

  public async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._importRawKey(key, false);
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

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    await this._setup();
    try {
      const dkpPrk = await this._hkdf.labeledExtract(
        EMPTY,
        LABEL_DKP_PRK,
        new Uint8Array(ikm),
      );
      const bn = new Bignum(this._nSk);
      for (
        let counter = 0;
        bn.isZero() || !bn.lessThan(this._order);
        counter++
      ) {
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
      const sk = await this._deserializePkcs8Key(bn.val());
      bn.reset();
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
    const pkcs8Key = new Uint8Array(
      this._pkcs8AlgId.length + k.length,
    );
    pkcs8Key.set(this._pkcs8AlgId, 0);
    pkcs8Key.set(k, this._pkcs8AlgId.length);
    return await (this._api as SubtleCrypto).importKey(
      "pkcs8",
      pkcs8Key,
      this._alg,
      true,
      KEM_USAGES,
    );
  }

  private async _derivePublicKeyWithoutJwkExport(
    key: CryptoKey,
  ): Promise<CryptoKey> {
    const basePointRaw = buildRawUncompressedPublicKey(
      this._curveParams.gx,
      this._curveParams.gy,
      this._curveParams.coordinateSize,
    );
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
        this._nDh * 8,
      ),
    );
    const p = this._curveParams.p;
    const x = bytesToBigInt(xBytes);
    const rhs = mod(
      modPow(x, BigInt(3), p) - BigInt(3) * x + this._curveParams.b,
      p,
    );
    let y = modSqrt(rhs, p);
    // Canonicalize sign so the encoded point is deterministic.
    if ((y & BigInt(1)) === BigInt(1)) {
      y = p - y;
    }
    const pubRaw = buildRawUncompressedPublicKey(
      x,
      y,
      this._curveParams.coordinateSize,
    );
    return await (this._api as SubtleCrypto).importKey(
      "raw",
      pubRaw.buffer as ArrayBuffer,
      this._alg,
      true,
      [],
    );
  }
}
