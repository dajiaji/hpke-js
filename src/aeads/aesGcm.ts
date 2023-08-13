import type { AeadEncryptionContext } from "../interfaces/aeadEncryptionContext.ts";
import type { AeadInterface } from "../interfaces/aeadInterface.ts";

import { NativeAlgorithm } from "../algorithm.ts";
import { AeadId } from "../identifiers.ts";
import { AEAD_USAGES } from "../interfaces/aeadEncryptionContext.ts";

export class AesGcmContext extends NativeAlgorithm
  implements AeadEncryptionContext {
  private _rawKey: ArrayBuffer;
  private _key: CryptoKey | undefined = undefined;

  public constructor(key: ArrayBuffer) {
    super();
    this._rawKey = key;
  }

  public async seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    await this._setupKey();
    const alg = {
      name: "AES-GCM",
      iv: iv,
      additionalData: aad,
    };
    const ct: ArrayBuffer = await (this._api as SubtleCrypto).encrypt(
      alg,
      this._key as CryptoKey,
      data,
    );
    return ct;
  }

  public async open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    await this._setupKey();
    const alg = {
      name: "AES-GCM",
      iv: iv,
      additionalData: aad,
    };
    const pt: ArrayBuffer = await (this._api as SubtleCrypto).decrypt(
      alg,
      this._key as CryptoKey,
      data,
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

export class Aes128Gcm implements AeadInterface {
  public readonly id: AeadId = AeadId.Aes128Gcm;
  public readonly keySize: number = 16;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;

  public createEncryptionContext(key: ArrayBuffer): AeadEncryptionContext {
    return new AesGcmContext(key);
  }
}

export class Aes256Gcm extends Aes128Gcm {
  public readonly id: AeadId = AeadId.Aes256Gcm;
  public readonly keySize: number = 32;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;
}
