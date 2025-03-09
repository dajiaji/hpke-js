import type { DhkemPrimitives, KdfInterface } from "@hpke/common";

import {
  base64UrlToBytes,
  DeriveKeyPairError,
  DeserializeError,
  EMPTY,
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
  NativeAlgorithm,
  NotSupportedError,
  SerializeError,
} from "@hpke/common";

const ALG_NAME = "X25519";

// deno-fmt-ignore
const PKCS8_ALG_ID_X25519 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

export class X25519 extends NativeAlgorithm implements DhkemPrimitives {
  private _hkdf: KdfInterface;
  private _alg: KeyAlgorithm;
  private _nPk: number;
  private _nSk: number;
  private _nDh: number;
  private _pkcs8AlgId: Uint8Array;

  constructor(hkdf: KdfInterface) {
    super();
    this._alg = { name: ALG_NAME };
    this._hkdf = hkdf;
    this._nPk = 32;
    this._nSk = 32;
    this._nDh = 32;
    this._pkcs8AlgId = PKCS8_ALG_ID_X25519;
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
        ALG_NAME,
        true,
        KEM_USAGES,
      ) as CryptoKeyPair;
    } catch (e: unknown) {
      throw new NotSupportedError(e);
    }
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    await this._setup();
    try {
      const dkpPrk = await this._hkdf.labeledExtract(
        EMPTY.buffer as ArrayBuffer,
        LABEL_DKP_PRK,
        new Uint8Array(ikm),
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
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      const bits = await (this._api as SubtleCrypto).deriveBits(
        {
          name: ALG_NAME,
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
    if (typeof key.crv === "undefined" || key.crv !== ALG_NAME) {
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
}
