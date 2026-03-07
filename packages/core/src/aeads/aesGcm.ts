import type { AeadEncryptionContext, AeadInterface } from "@hpke/common";
import {
  AEAD_USAGES,
  AeadId,
  NativeAlgorithm,
  toArrayBuffer,
} from "@hpke/common";

export class AesGcmContext extends NativeAlgorithm
  implements AeadEncryptionContext {
  private _rawKey: ArrayBuffer;
  private _key: CryptoKey | undefined = undefined;

  public constructor(key: ArrayBufferLike | ArrayBufferView) {
    super();
    this._rawKey = toArrayBuffer(key);
  }

  public async seal(
    iv: ArrayBufferLike | ArrayBufferView,
    data: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    await this._setupKey();
    const alg = {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aad),
    };
    const ct: ArrayBuffer = await (this._api as SubtleCrypto).encrypt(
      alg,
      this._key as CryptoKey,
      toArrayBuffer(data),
    );
    return ct;
  }

  public async open(
    iv: ArrayBufferLike | ArrayBufferView,
    data: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    await this._setupKey();
    const alg = {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(aad),
    };
    const pt: ArrayBuffer = await (this._api as SubtleCrypto).decrypt(
      alg,
      this._key as CryptoKey,
      toArrayBuffer(data),
    );
    return pt;
  }

  protected async _setupKey() {
    if (this._key !== undefined) {
      return;
    }
    await this._setup();
    const key = await this._importKey(this._rawKey);
    (new Uint8Array(this._rawKey)).fill(0);
    this._key = key;
    return;
  }

  private async _importKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await (this._api as SubtleCrypto).importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      true,
      AEAD_USAGES,
    );
  }
}

/**
 * The AES-128-GCM for HPKE AEAD implementing {@link AeadInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `aead` parameter of {@link CipherSuiteParams} instead of `AeadId.Aes128Gcm`.
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class Aes128Gcm implements AeadInterface {
  /** AeadId.Aes128Gcm (0x0001) */
  public readonly id: AeadId = AeadId.Aes128Gcm;
  /** 16 */
  public readonly keySize: number = 16;
  /** 12 */
  public readonly nonceSize: number = 12;
  /** 16 */
  public readonly tagSize: number = 16;

  public createEncryptionContext(
    key: ArrayBufferLike | ArrayBufferView,
  ): AeadEncryptionContext {
    return new AesGcmContext(key);
  }
}

/**
 * The AES-256-GCM for HPKE AEAD implementing {@link AeadInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `aead` parameter of {@link CipherSuiteParams} instead of `AeadId.Aes256Gcm`
 * as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes256Gcm,
 *   CipherSuite,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes256Gcm(),
 * });
 * ```
 */
export class Aes256Gcm extends Aes128Gcm {
  /** AeadId.Aes256Gcm (0x0002) */
  override id: AeadId = AeadId.Aes256Gcm;
  /** 32 */
  override keySize: number = 32;
  /** 12 */
  override nonceSize: number = 12;
  /** 16 */
  override tagSize: number = 16;
}
