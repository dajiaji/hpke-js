import {
  MlKem1024 as MlKem1024Native,
  MlKem512 as MlKem512Native,
  MlKem768 as MlKem768Native,
  // @ts-ignore: Unreachable code error
} from "@dajiaji/mlkem";

import type {
  JsonWebKeyExtended,
  KemInterface,
  RecipientContextParams,
  SenderContextParams,
} from "@hpke/common";

import {
  base64UrlToBytes,
  concat,
  DecapError,
  DeriveKeyPairError,
  DeserializeError,
  EncapError,
  InvalidParamError,
  isCryptoKeyPair,
  KEM_USAGES,
  KemId,
  loadCrypto,
  NotSupportedError,
  SerializeError,
  XCryptoKey,
} from "@hpke/common";

interface MlKemInterface {
  generateKeyPair(): Promise<[Uint8Array, Uint8Array]>;
  deriveKeyPair(seed: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
  encap(pk: Uint8Array, seed?: Uint8Array): Promise<[Uint8Array, Uint8Array]>;
  decap(ct: Uint8Array, sk: Uint8Array): Promise<Uint8Array>;
}

/**
 * The base class of ML-KEM.
 */
export class MlKemBase implements KemInterface {
  public readonly id: KemId = 0;
  public readonly name: string = "";
  public readonly secretSize: number = 0;
  public readonly encSize: number = 0;
  public readonly publicKeySize: number = 0;
  public readonly privateKeySize: number = 0;
  public readonly auth: boolean = false;
  protected _prim: MlKemInterface | undefined = undefined;
  private _api: Crypto | undefined = undefined;

  constructor() {}

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    try {
      return await this._deserializePublicKey(key);
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
      return await this._deserializePrivateKey(key);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    await this._setup();
    const d = new Uint8Array(32);
    const z = new Uint8Array(32);
    try {
      (this._api as Crypto).getRandomValues(d);
      (this._api as Crypto).getRandomValues(z);
    } catch (e: unknown) {
      throw new NotSupportedError(e);
    }
    try {
      const sk = concat(d, z);
      const [pk, _sk] = await (this._prim as MlKemInterface).deriveKeyPair(sk);
      const dSk = await this.deserializePrivateKey(sk.buffer as ArrayBuffer);
      const dPk = await this.deserializePublicKey(pk.buffer as ArrayBuffer);
      return { privateKey: dSk, publicKey: dPk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    try {
      const [pk, _] = await (this._prim as MlKemInterface).deriveKeyPair(
        new Uint8Array(ikm),
      );
      const dSk = await this.deserializePrivateKey(ikm);
      const dPk = await this.deserializePublicKey(pk.buffer as ArrayBuffer);
      return { privateKey: dSk, publicKey: dPk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKeyExtended,
    isPublic = true,
  ): Promise<CryptoKey> {
    await this._setup();
    try {
      let ret: Uint8Array;
      if (format === "jwk") {
        if (key instanceof ArrayBuffer || key instanceof Uint8Array) {
          throw new Error("Invalid jwk key format");
        }
        ret = await this._importJWK(key as JsonWebKey, isPublic);
      } else {
        if (key instanceof ArrayBuffer) {
          ret = new Uint8Array(key);
        } else if (key instanceof Uint8Array) {
          ret = key;
        } else {
          throw new Error("Invalid key format");
        }
      }
      if (isPublic && ret.byteLength !== this.publicKeySize) {
        throw new Error("Invalid length of the key");
      }
      if (!isPublic && ret.byteLength !== this.privateKeySize) {
        throw new Error("Invalid length of the key");
      }
      return new XCryptoKey(
        this.name,
        ret,
        isPublic ? "public" : "private",
        isPublic ? [] : KEM_USAGES,
      );
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    let ekm: Uint8Array | undefined = undefined;
    if (params.ekm !== undefined) {
      if (params.ekm instanceof ArrayBuffer) {
        ekm = new Uint8Array(params.ekm);
      } else if (params.ekm instanceof Uint8Array) {
        ekm = params.ekm;
      } else {
        throw new InvalidParamError("ekm must be 32 bytes in length");
      }
    }
    const pk = new Uint8Array(
      await this.serializePublicKey(params.recipientPublicKey),
    );
    if (pk.byteLength !== this.publicKeySize) {
      throw new InvalidParamError("Invalid length of recipientKey");
    }
    try {
      const [ct, ss] = await (this._prim as MlKemInterface).encap(pk, ekm);
      return {
        sharedSecret: ss.buffer.slice(
          ss.byteOffset,
          ss.byteOffset + ss.byteLength,
        ) as ArrayBuffer,
        enc: ct.buffer as ArrayBuffer,
      };
    } catch (e: unknown) {
      throw new EncapError(e);
    }
  }

  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const rSk = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.privateKey
      : params.recipientKey;
    if (params.enc.byteLength !== this.encSize) {
      throw new InvalidParamError("Invalid length of enc");
    }
    const ct = new Uint8Array(params.enc);
    const sk = new Uint8Array(await this.serializePrivateKey(rSk));
    if (sk.byteLength !== this.privateKeySize) {
      throw new InvalidParamError("Invalid length of recipientKey");
    }
    try {
      const [_, exSk] = await (this._prim as MlKemInterface).deriveKeyPair(sk);
      const ss = await (this._prim as MlKemInterface).decap(ct, exSk);
      return ss.buffer.slice(
        ss.byteOffset,
        ss.byteOffset + ss.byteLength,
      ) as ArrayBuffer;
    } catch (e: unknown) {
      throw new DecapError(e);
    }
  }

  private async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadCrypto();
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      if (k.type !== "public") {
        reject(new Error("Not public key"));
      }
      if (k.algorithm.name !== this.name) {
        reject(new Error(`Invalid algorithm name: ${k.algorithm.name}`));
      }
      if (k.key.byteLength !== this.publicKeySize) {
        reject(new Error(`Invalid key length: ${k.key.byteLength}`));
      }
      resolve(k.key.buffer as ArrayBuffer);
    });
  }

  private _deserializePublicKey(k: ArrayBuffer): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (k.byteLength !== this.publicKeySize) {
        reject(new Error(`Invalid key length: ${k.byteLength}`));
      }
      resolve(new XCryptoKey(this.name, new Uint8Array(k), "public"));
    });
  }

  private _serializePrivateKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      if (k.type !== "private") {
        reject(new Error("Not private key"));
      }
      if (k.algorithm.name !== this.name) {
        reject(new Error(`Invalid algorithm name: ${k.algorithm.name}`));
      }
      if (k.key.byteLength !== this.privateKeySize) {
        reject(new Error(`Invalid key length: ${k.key.byteLength}`));
      }
      resolve(k.key.buffer as ArrayBuffer);
    });
  }

  private _deserializePrivateKey(k: ArrayBuffer): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (k.byteLength !== this.privateKeySize) {
        reject(new Error(`Invalid key length: ${k.byteLength}`));
      }
      resolve(
        new XCryptoKey(this.name, new Uint8Array(k), "private", ["deriveBits"]),
      );
    });
  }

  private _importJWK(
    key: JsonWebKeyExtended,
    isPublic: boolean,
  ): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      if (typeof key.kty === "undefined" || key.kty !== "AKP") {
        reject(new Error(`Invalid kty: ${key.kty}`));
      }
      if (typeof key.alg === "undefined" || key.alg !== this.name) {
        reject(new Error(`Invalid alg: ${key.alg}`));
      }
      if (!isPublic) {
        if (typeof key.priv === "undefined") {
          reject(new Error("Invalid key: `priv` not found"));
        }
        if (
          typeof key.key_ops !== "undefined" &&
          (key.key_ops.length !== 1 || key.key_ops[0] !== "deriveBits")
        ) {
          reject(new Error("Invalid key: `key_ops` should be ['deriveBits']"));
        }
        resolve(base64UrlToBytes(key.priv as string));
      }
      if (typeof key.priv !== "undefined") {
        reject(new Error("Invalid key: `priv` should not be set"));
      }
      if (typeof key.pub === "undefined") {
        reject(new Error("Invalid key: `pub` not found"));
      }
      if (typeof key.key_ops !== "undefined" && key.key_ops.length > 0) {
        reject(new Error("Invalid key: `key_ops` should not be set"));
      }
      resolve(base64UrlToBytes(key.pub as string));
    });
  }
}

/**
 * The ML-KEM-512 for HPKE KEM implementing {@link KemInterface}.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
 * import { MlKem512 } from "@hpke/ml-kem";
 * const suite = new CipherSuite({
 *   kem: new MlKem512(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class MlKem512 extends MlKemBase {
  override id: KemId = KemId.MlKem512;
  override name: string = "ML-KEM-512";
  override secretSize: number = 32;
  override encSize: number = 768;
  override publicKeySize: number = 800;
  override privateKeySize: number = 64;
  override auth = false;
  override _prim: MlKemInterface | undefined = undefined;

  constructor() {
    super();
    this._prim = new MlKem512Native();
  }
}

/**
 * The ML-KEM-768 for HPKE KEM implementing {@link KemInterface}.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import { Aes256Gcm, CipherSuite, HkdfSha384 } from "@hpke/core";
 * import { MlKem768 } from "@hpke/ml-kem";
 * const suite = new CipherSuite({
 *   kem: new MlKem768(),
 *   kdf: new HkdfSha384(),
 *   aead: new Aes256Gcm(),
 * });
 * ```
 */
export class MlKem768 extends MlKemBase {
  override id: KemId = KemId.MlKem768;
  override name: string = "ML-KEM-768";
  override secretSize: number = 32;
  override encSize: number = 1088;
  override publicKeySize: number = 1184;
  override privateKeySize: number = 64;
  override auth = false;
  override _prim: MlKemInterface | undefined = undefined;

  constructor() {
    super();
    this._prim = new MlKem768Native();
  }
}

/**
 * The ML-KEM-1024 for HPKE KEM implementing {@link KemInterface}.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import { Aes256Gcm, CipherSuite, HkdfSha512 } from "@hpke/core";
 * import { MlKem1024 } from "@hpke/ml-kem";
 * const suite = new CipherSuite({
 *   kem: new MlKem1024(),
 *   kdf: new HkdfSha512(),
 *   aead: new Aes256Gcm(),
 * });
 * ```
 */
export class MlKem1024 extends MlKemBase {
  override id: KemId = KemId.MlKem1024;
  override name: string = "ML-KEM-1024";
  override secretSize: number = 32;
  override encSize: number = 1568;
  override publicKeySize: number = 1568;
  override privateKeySize: number = 64;
  override auth = false;
  override _prim: MlKemInterface | undefined = undefined;

  constructor() {
    super();
    this._prim = new MlKem1024Native();
  }
}
