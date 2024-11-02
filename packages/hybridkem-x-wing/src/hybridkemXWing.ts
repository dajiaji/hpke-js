import { sha3_256, shake256 } from "@noble/hashes/sha3";
import { MlKem768 } from "@dajiaji/mlkem";

import type {
  KemInterface,
  RecipientContextParams,
  SenderContextParams,
} from "@hpke/common";

import {
  concat,
  DecapError,
  DeriveKeyPairError,
  DeserializeError,
  EncapError,
  InvalidParamError,
  isCryptoKeyPair,
  KemId,
  loadCrypto,
  NotSupportedError,
  SerializeError,
  XCryptoKey,
} from "@hpke/common";

import { HkdfSha256, X25519 } from "@hpke/dhkem-x25519";

// deno-fmt-ignore
const X25519_BASE = new Uint8Array([
  0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

// XWingLabel = concat(
//   "\./",
//   "/^\",
// );
// deno-fmt-ignore
const XWING_LABEL = new Uint8Array([46, 47, 47, 94, 92]);

function emitNotSupported<T>(): Promise<T> {
  return new Promise((_resolve, reject) => {
    reject(new NotSupportedError("Not supported"));
  });
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
 * import { HybridkemXWing } from "@hpke/hybridkem-x-wing";
 * const suite = new CipherSuite({
 *   kem: new HybridkemXWing(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class HybridkemXWing implements KemInterface {
  public readonly id: KemId = KemId.HybridkemXWing;
  public readonly name: string = "X-Wing";
  public readonly secretSize: number = 32;
  public readonly encSize: number = 1120;
  public readonly publicKeySize: number = 1216;
  public readonly privateKeySize: number = 32;
  public readonly auth: boolean = false;
  protected _m: MlKem768;
  protected _x25519: X25519;
  private _api: Crypto | undefined = undefined;

  constructor() {
    this._m = new MlKem768();
    this._x25519 = new X25519(new HkdfSha256());
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    await this._setup();
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._deserializePublicKey(key);
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

  public async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    await this._setup();
    try {
      return await this._deserializePrivateKey(key);
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
      const dSk = await this.deserializePrivateKey(sk);
      const dPk = await this.deserializePublicKey(pk);
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
      const dSk = await this.deserializePrivateKey(sk);
      const dPk = await this.deserializePublicKey(pk);
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
  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    await this._setup();
    try {
      const sk = shake256.create({ dkLen: 32 })
        .update(new Uint8Array(ikm))
        .digest();
      const [_sk, pk] = await this._generateKeyPairDerand(sk);
      const dSk = await this.deserializePrivateKey(sk);
      const dPk = await this.deserializePublicKey(pk);
      return { privateKey: dSk, publicKey: dPk };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async importKey(
    _format: "raw" | "jwk",
    _key: ArrayBuffer | JsonWebKey,
    _isPublic = true,
  ): Promise<CryptoKey> {
    return await emitNotSupported<CryptoKey>();
    // if (format !== "raw") {
    //   throw new NotSupportedError("'jwk' is not supported");
    // }
    // if (!(key instanceof ArrayBuffer)) {
    //   throw new InvalidParamError("Invalid type of key");
    // }
    // if (isPublic) {
    //   return await this.deserializePublicKey(key as ArrayBuffer);
    // }
    // return await this.deserializePrivateKey(key as ArrayBuffer);
  }

  public async encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }> {
    let ekm: ArrayBuffer | undefined = undefined;
    if (params.ekm !== undefined && !isCryptoKeyPair(params.ekm)) {
      if (params.ekm.byteLength !== 64) {
        throw new InvalidParamError("ekm must be 64 bytes in length");
      }
      ekm = params.ekm;
    }
    let ekM: Uint8Array | undefined = undefined;
    let ekX: Uint8Array;
    if (ekm !== undefined) {
      const ek = new Uint8Array(ekm);
      ekM = ek.subarray(0, 32);
      ekX = ek.subarray(32, 64);
    } else {
      ekX = new Uint8Array(32);
      try {
        (this._api as Crypto).getRandomValues(ekX);
      } catch (e: unknown) {
        throw new NotSupportedError(e);
      }
    }
    const pk = new Uint8Array(
      await this.serializePublicKey(params.recipientPublicKey),
    );
    if (pk.byteLength !== 1216) {
      throw new InvalidParamError("Invalid length of recipientPublicKey");
    }
    await this._setup();
    try {
      const pkM = pk.subarray(0, 1184);
      const pkX = pk.subarray(1184, 1216);
      const ctX = await this._x25519.derive(ekX, X25519_BASE);
      const ssX = await this._x25519.derive(ekX, pkX);
      const [ctM, ssM] = await this._m.encap(pkM, ekM);
      return {
        sharedSecret: combiner(ssM, ssX, ctX, pkX),
        enc: concat(ctM, ctX),
      };
    } catch (e: unknown) {
      throw new EncapError(e);
    }
  }

  public async decap(params: RecipientContextParams): Promise<ArrayBuffer> {
    const rSk = isCryptoKeyPair(params.recipientKey)
      ? params.recipientKey.privateKey
      : params.recipientKey;
    if (params.enc.byteLength !== 1120) {
      throw new InvalidParamError("Invalid length of enc");
    }
    const sk = new Uint8Array(await this.serializePrivateKey(rSk));
    if (sk.byteLength !== 32) {
      throw new InvalidParamError("Invalid length of recipientKey");
    }
    await this._setup();
    try {
      const [skM, skX, _pkM, pkX] = await this._expandDecapsulationKey(sk);
      const ct = new Uint8Array(params.enc);
      const ctM = ct.subarray(0, 1088);
      const ctX = ct.subarray(1088);
      const ssM = await this._m.decap(ctM, skM);
      const ssX = await this._x25519.derive(skX, ctX);
      return combiner(ssM, ssX, ctX, pkX);
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
    const pkX = await this._x25519.derive(skX, X25519_BASE);
    return [skM, skX, pkM, pkX];
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
      resolve(k.key.buffer);
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
      resolve(k.key.buffer);
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
}
