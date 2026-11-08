// @ts-ignore: Unreachable code error
import { MlKem768, sha3_256, shake256 } from "@dajiaji/mlkem";

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
  loadCrypto,
  NotSupportedError,
  SerializeError,
  toArrayBuffer,
  x25519,
  XCryptoKey,
} from "@hpke/common";
import type { KemId } from "@hpke/common";

const ALG_NAME = "X-Wing";

// XWingLabel = concat(
//   "\./",
//   "/^\",
// );
// deno-fmt-ignore
const XWING_LABEL = new Uint8Array([92, 46, 47, 47, 94, 92]);

// The DER-encoded PKCS #8 PrivateKeyInfo prefix for a raw 32-byte X25519
// private key (RFC 8410).
// deno-fmt-ignore
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

// X25519 field prime: 2^255 - 19
const X25519_P =
  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;

// The u-coordinates whose order divides the cofactor (on the curve and on its
// quadratic twist). Same blocklist as the Montgomery ladder of @hpke/common
// (and libsodium). Non-canonical encodings are reduced modulo p first, so
// p and p + 1 collapse onto 0 and 1.
const X25519_LOW_ORDER_U = new Set<bigint>([
  0n,
  1n,
  X25519_P - 1n,
  325606250916557431795983626356110631294008115727848805560023387167927233504n,
  39382357235489614581723060781553021112529911719440698176882885853963445705823n,
]);

/**
 * Checks whether the X25519 public key (u-coordinate) is of low order.
 * The u-coordinate is decoded as in RFC 7748: the most significant bit is
 * masked, and non-canonical values are reduced modulo p.
 */
function isLowOrderX25519(u: Uint8Array): boolean {
  let n = 0n;
  for (let i = 31; i >= 0; i--) {
    n = (n << 8n) | BigInt(i === 31 ? u[i] & 0x7f : u[i]);
  }
  return X25519_LOW_ORDER_U.has(n % X25519_P);
}

function combiner(
  ssM: Uint8Array,
  ssX: Uint8Array,
  ctX: Uint8Array,
  pkX: Uint8Array,
): Uint8Array {
  const ret = new Uint8Array(
    ssM.length + ssX.length + ctX.length + pkX.length + XWING_LABEL.length,
  );
  ret.set(ssM, 0);
  ret.set(ssX, ssM.length);
  ret.set(ctX, ssM.length + ssX.length);
  ret.set(pkX, ssM.length + ssX.length + ctX.length);
  ret.set(XWING_LABEL, ssM.length + ssX.length + ctX.length + pkX.length);
  return sha3_256.create().update(ret).digest();
}

/**
 * The Hybrid Post-Quantum KEM (X25519, Kyber768).
 *
 * This class is implemented using
 * {@link https://github.com/Argyle-Software/kyber | pqc-kyber }.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example Use with `@hpke/core`:
 *
 * ```ts
 * import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
 * import { XWing } from "@hpke/hybridkem-x-wing";
 * const suite = new CipherSuite({
 *   kem: new XWing(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class XWing implements KemInterface {
  public readonly id: KemId = 0x647a; // KemId.XWing
  public readonly name: string = ALG_NAME;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 1120;
  public readonly publicKeySize: number = 1216;
  public readonly privateKeySize: number = 32;
  public readonly auth: boolean = false;
  protected _m: MlKem768;
  private _api: Crypto | undefined = undefined;
  // Whether the Web Cryptography API supports X25519.
  // `undefined` means it has not been probed yet.
  private _nativeX25519: boolean | undefined = undefined;

  constructor() {
    this._m = new MlKem768();
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._deserializePublicKey(toArrayBuffer(key));
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      return await this._serializePrivateKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePrivateKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._deserializePrivateKey(toArrayBuffer(key));
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  /**
   * Generates a new key pair.
   *
   * @returns {Promise<CryptoKeyPair>} A promise that resolves with a new key pair.
   */
  public async generateKeyPair(): Promise<CryptoKeyPair> {
    await this._setup();
    const sk = new Uint8Array(32);
    try {
      (this._api as Crypto).getRandomValues(sk);
    } catch (e: unknown) {
      throw new NotSupportedError(e);
    }
    try {
      const [_sk, pk] = await this._generateKeyPairDerand(sk);
      const dSk = await this.deserializePrivateKey(sk.buffer as ArrayBuffer);
      const dPk = await this.deserializePublicKey(pk.buffer as ArrayBuffer);
      return { privateKey: dSk, publicKey: dPk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  /**
   * Generates a key pair from the secret key.
   * @param sk The secret key.
   * @returns {Promise<CryptoKeyPair>} A promise that resolves with a new key pair.
   * @throws {InvalidParamError} Thrown if the length of the secret key is not 32 bytes.
   * @throws {DeriveKeyPairError} Thrown if the key pair cannot be derived.
   */
  public async generateKeyPairDerand(sk: Uint8Array): Promise<CryptoKeyPair> {
    if (sk.byteLength !== 32) {
      throw new InvalidParamError("Invalid length of sk");
    }
    try {
      const [_sk, pk] = await this._generateKeyPairDerand(sk);
      const dSk = await this.deserializePrivateKey(sk.buffer as ArrayBuffer);
      const dPk = await this.deserializePublicKey(pk.buffer as ArrayBuffer);
      return { privateKey: dSk, publicKey: dPk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  /**
   * Derives a key pair from the input keying material.
   *
   * @param {ArrayBuffer} ikm The input keying material.
   * @returns {Promise<CryptoKeyPair>} A promise that resolves with a new key pair.
   * @throws {DeriveKeyPairError} Thrown if the key pair cannot be derived.
   * @throws {InvalidParamError} Thrown if the length of the IKM is not 32 bytes.
   */
  public async deriveKeyPair(
    ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKeyPair> {
    await this._setup();
    try {
      const rawIkm = toArrayBuffer(ikm);
      const sk = shake256.create({ dkLen: 32 })
        .update(new Uint8Array(rawIkm))
        .digest();
      const [_sk, pk] = await this._generateKeyPairDerand(sk);
      const dSk = await this.deserializePrivateKey(sk.buffer as ArrayBuffer);
      const dPk = await this.deserializePublicKey(pk.buffer as ArrayBuffer);
      return { privateKey: dSk, publicKey: dPk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  /**
   * Imports a key from the input.
   * @param format The format of the key. "raw" or "jwk" can be specified.
   * @param key The key to import. If the format is "raw", the key must be an ArrayBuffer. If the format is "jwk", the key must be a JsonWebKey.
   * @param isPublic A boolean indicating whether the key is public or not. The default is true.
   * @returns {Promise<CryptoKey>} A promise that resolves with the imported key.
   * @throws {DeserializeError} Thrown if the key cannot be imported.
   */
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
        ALG_NAME,
        ret,
        isPublic ? "public" : "private",
        isPublic ? [] : KEM_USAGES,
      );
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  /**
   * Encapsulates the shared secret and the `ct` (ciphertext) as `enc`.
   * @param params The parameters for encapsulation.
   * @returns {Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }>} A promise that resolves with the `ss` (shared secret) as `sharedSecret` and the `ct` (ciphertext) as `enc`.
   * @throws {InvalidParamError} Thrown if the length of the `ekm` is not 64 bytes.
   * @throws {EncapError} Thrown if the shared secret cannot be encapsulated.
   * @throws {NotSupportedError} if `senderKey` is provided.
   */
  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    if (params.senderKey !== undefined) {
      throw new NotSupportedError(
        "Auth and AuthPSK modes are not supported by this KEM",
      );
    }
    let ekm: ArrayBuffer | undefined = undefined;
    if (params.ekm !== undefined && !isCryptoKeyPair(params.ekm)) {
      ekm = toArrayBuffer(params.ekm as ArrayBufferLike);
      if (ekm.byteLength !== 64) {
        throw new InvalidParamError("ekm must be 64 bytes in length");
      }
    }
    await this._setup();
    let ekM: Uint8Array | undefined = undefined;
    let ekX: Uint8Array;
    if (ekm !== undefined) {
      const ek = new Uint8Array(ekm);
      ekM = ek.subarray(0, 32);
      ekX = ek.subarray(32, 64);
    } else {
      const randomEkX = new Uint8Array(32);
      try {
        (this._api as Crypto).getRandomValues(randomEkX);
      } catch (e: unknown) {
        throw new NotSupportedError(e);
      }
      ekX = randomEkX;
    }
    const pk = new Uint8Array(
      await this.serializePublicKey(params.recipientPublicKey),
    );
    if (pk.byteLength !== 1216) {
      throw new InvalidParamError("Invalid length of recipientPublicKey");
    }
    try {
      const pkM = pk.subarray(0, 1184);
      const pkX = pk.subarray(1184, 1216);
      const ctX = await this._x25519PublicKey(ekX);
      const ssX = await this._x25519SharedSecret(ekX, pkX);
      const [ctM, ssM] = await this._m.encap(pkM, ekM);
      return {
        sharedSecret: combiner(ssM, ssX, ctX, pkX).buffer as ArrayBuffer,
        enc: concat(ctM, ctX).buffer as ArrayBuffer,
      };
    } catch (e: unknown) {
      throw new EncapError(e);
    }
  }

  /**
   * Decapsulates the `ss` (shared secret) from the `enc` and the recipient's private key.
   * The `enc` is the same as the `ct` (ciphertext) resulting from `X-Wing::Encapsulate(),
   * which is executed under the `encap()`.
   * @param params The parameters for decapsulation.
   * @returns {Promise<ArrayBuffer>} A promise that resolves with the shared secret.
   * @throws {InvalidParamError} Thrown if the length of the `enc` is not 1120 bytes.
   * @throws {DecapError} Thrown if the shared secret cannot be decapsulated.
   * @throws {NotSupportedError} if `senderPublicKey` is provided.
   */
  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    if (params.senderPublicKey !== undefined) {
      throw new NotSupportedError(
        "Auth and AuthPSK modes are not supported by this KEM",
      );
    }
    const enc = toArrayBuffer(params.enc);
    const rSk = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.privateKey
      : params.recipientKey;
    if (enc.byteLength !== 1120) {
      throw new InvalidParamError("Invalid length of enc");
    }
    const sk = new Uint8Array(await this.serializePrivateKey(rSk));
    if (sk.byteLength !== 32) {
      throw new InvalidParamError("Invalid length of recipientKey");
    }
    await this._setup();
    try {
      const [skM, skX, _pkM, pkX] = await this._expandDecapsulationKey(sk);
      const ct = new Uint8Array(enc);
      const ctM = ct.subarray(0, 1088);
      const ctX = ct.subarray(1088);
      const ssM = await this._m.decap(ctM, skM);
      const ssX = await this._x25519SharedSecret(skX, ctX);
      return combiner(ssM, ssX, ctX, pkX).buffer as ArrayBuffer;
    } catch (e: unknown) {
      throw new DecapError(e);
    }
  }

  /**
   * Sets up the MlKemBase instance by loading the necessary crypto library.
   * If the crypto library is already loaded, this method does nothing.
   * @returns {Promise<void>} A promise that resolves when the setup is complete.
   */
  private async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadCrypto();
  }

  /**
   * Generates a key pair from the secret key.
   * @param sk The secret key.
   * @returns {Promise<[Uint8Array, Uint8Array]>} A promise that resolves with the key pair derived from the secret key.
   */
  private async _generateKeyPairDerand(
    sk: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array]> {
    const [_skM, _skX, pkM, pkX] = await this._expandDecapsulationKey(sk);
    return [sk, concat(pkM, pkX)];
  }

  /**
   * Expands the decapsulation key.
   * @param sk The secret key.
   * @returns {Promise<[Uint8Array, Uint8Array, Uint8Array, Uint8Array]>} A promise that resolves with the keys derived by expanding the secret key.
   */
  private async _expandDecapsulationKey(
    sk: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array, Uint8Array, Uint8Array]> {
    const expanded = shake256.create({ dkLen: 96 }).update(sk).digest();
    const [pkM, skM] = await this._m.deriveKeyPair(expanded.subarray(0, 64));
    const skX = expanded.subarray(64, 96);
    const pkX = await this._x25519PublicKey(skX);
    return [skM, skX, pkM, pkX];
  }

  /**
   * Imports the raw X25519 private key into the Web Cryptography API.
   *
   * On the first call, this also probes whether the Web Cryptography API
   * supports X25519. If it does not, `undefined` is returned and the
   * JavaScript implementation is used from then on.
   * @param sk The raw 32-byte X25519 private key.
   * @param extractable Whether the imported key can be exported.
   * @returns {Promise<CryptoKey | undefined>} A promise that resolves with the imported key, or `undefined` if X25519 is not supported.
   */
  private async _importX25519PrivateKey(
    sk: Uint8Array,
    extractable: boolean,
  ): Promise<CryptoKey | undefined> {
    if (this._nativeX25519 === false) {
      return undefined;
    }
    await this._setup();
    const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + sk.length);
    pkcs8.set(X25519_PKCS8_PREFIX, 0);
    pkcs8.set(sk, X25519_PKCS8_PREFIX.length);
    try {
      const key = await (this._api as Crypto).subtle.importKey(
        "pkcs8",
        pkcs8,
        { name: "X25519" },
        extractable,
        ["deriveBits"],
      );
      this._nativeX25519 = true;
      return key;
    } catch (e: unknown) {
      if (this._nativeX25519 === true) {
        throw e;
      }
      // X25519 is not supported by the Web Cryptography API.
      this._nativeX25519 = false;
      return undefined;
    } finally {
      pkcs8.fill(0);
    }
  }

  /**
   * Computes the X25519 public key for the private key.
   *
   * The fixed-base scalar multiplication is delegated to the Web Cryptography
   * API when it supports X25519, which is much faster than the JavaScript
   * Montgomery ladder. Otherwise, it falls back to the JavaScript
   * implementation.
   * @param sk The raw 32-byte X25519 private key.
   * @returns {Promise<Uint8Array>} A promise that resolves with the raw 32-byte public key.
   */
  private async _x25519PublicKey(sk: Uint8Array): Promise<Uint8Array> {
    const key = await this._importX25519PrivateKey(sk, true);
    if (key === undefined) {
      return x25519.getPublicKey(sk);
    }
    const jwk = await (this._api as Crypto).subtle.exportKey("jwk", key);
    const pk = base64UrlToBytes(jwk.x as string);
    if (pk.byteLength !== 32) {
      throw new Error("Invalid length of X25519 public key");
    }
    return pk;
  }

  /**
   * Computes the X25519 shared secret.
   *
   * Low-order public keys are rejected before any computation with the
   * private key, in the same way as the JavaScript implementation. The
   * scalar multiplication is delegated to the Web Cryptography API when it
   * supports X25519. Otherwise, it falls back to the JavaScript
   * implementation.
   * @param sk The raw 32-byte X25519 private key.
   * @param pk The raw 32-byte X25519 public key (u-coordinate).
   * @returns {Promise<Uint8Array>} A promise that resolves with the raw 32-byte shared secret.
   */
  private async _x25519SharedSecret(
    sk: Uint8Array,
    pk: Uint8Array,
  ): Promise<Uint8Array> {
    if (pk.byteLength !== 32) {
      throw new Error("Invalid length of X25519 public key");
    }
    if (isLowOrderX25519(pk)) {
      throw new Error("invalid private or public key received");
    }
    const key = await this._importX25519PrivateKey(sk, false);
    if (key === undefined) {
      return x25519.getSharedSecret(sk, pk);
    }
    const subtle = (this._api as Crypto).subtle;
    const pub = await subtle.importKey(
      "raw",
      toArrayBuffer(pk),
      { name: "X25519" },
      true,
      [],
    );
    const ss = new Uint8Array(
      await subtle.deriveBits({ name: "X25519", public: pub }, key, 256),
    );
    // Unreachable after the low-order check; kept as defense in depth.
    if (ss.every((b) => b === 0)) {
      throw new Error("invalid private or public key received");
    }
    return ss;
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
      if (typeof key.alg === "undefined" || key.alg !== ALG_NAME) {
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
