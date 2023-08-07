import type { AeadEncryptionContext } from "../interfaces/aeadEncryptionContext.ts";
import type { AeadInterface } from "../interfaces/aeadInterface.ts";

import { Algorithm } from "../algorithm.ts";
import { AeadId } from "../identifiers.ts";
import { AEAD_USAGES } from "../interfaces/aeadEncryptionContext.ts";

export class AesGcmContext implements AeadEncryptionContext {
  private _rawKey: ArrayBuffer;
  private _key: CryptoKey | undefined = undefined;
  private _api: SubtleCrypto;

  public constructor(api: SubtleCrypto, key: ArrayBuffer) {
    this._api = api;
    this._rawKey = key;
  }

  public async seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (this._key === undefined) {
      this._key = await this._importKey(this._rawKey);
      (new Uint8Array(this._rawKey)).fill(0);
    }
    const alg = {
      name: "AES-GCM",
      iv: iv,
      additionalData: aad,
    };
    const ct: ArrayBuffer = await this._api.encrypt(
      alg,
      this._key,
      data,
    );
    return ct;
  }

  public async open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (this._key === undefined) {
      this._key = await this._importKey(this._rawKey);
      (new Uint8Array(this._rawKey)).fill(0);
    }
    const alg = {
      name: "AES-GCM",
      iv: iv,
      additionalData: aad,
    };
    const pt: ArrayBuffer = await this._api.decrypt(
      alg,
      this._key,
      data,
    );
    return pt;
  }

  private async _importKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._api.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      true,
      AEAD_USAGES,
    );
  }
}

export class Aes128Gcm extends Algorithm implements AeadInterface {
  public readonly id: AeadId = AeadId.Aes128Gcm;
  public readonly keySize: number = 16;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;

  public createEncryptionContext(key: ArrayBuffer): AeadEncryptionContext {
    this.checkInit();
    return new AesGcmContext(this._api as SubtleCrypto, key);
  }
}

export class Aes256Gcm extends Algorithm implements AeadInterface {
  public readonly id: AeadId = AeadId.Aes256Gcm;
  public readonly keySize: number = 32;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;

  public createEncryptionContext(key: ArrayBuffer): AeadEncryptionContext {
    this.checkInit();
    return new AesGcmContext(this._api as SubtleCrypto, key);
  }
}
