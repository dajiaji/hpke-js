import type { AeadKey } from "../interfaces/aeadKey.ts";

import * as consts from "../consts.ts";

export class AesGcmKey implements AeadKey {
  private _rawKey: ArrayBuffer;
  private _key: CryptoKey | undefined = undefined;
  private _api: SubtleCrypto;

  public constructor(key: ArrayBuffer, api: SubtleCrypto) {
    this._rawKey = key;
    this._api = api;
  }

  public async seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (this._key === undefined) {
      this._key = await this.importKey(this._rawKey);
      (new Uint8Array(this._rawKey)).fill(0);
    }
    const alg = {
      name: "AES-GCM",
      iv: iv,
      additionalData: aad,
    };
    const ct: ArrayBuffer = await this._api.encrypt(alg, this._key, data);
    return ct;
  }

  public async open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (this._key === undefined) {
      this._key = await this.importKey(this._rawKey);
      (new Uint8Array(this._rawKey)).fill(0);
    }
    const alg = {
      name: "AES-GCM",
      iv: iv,
      additionalData: aad,
    };
    const pt: ArrayBuffer = await this._api.decrypt(alg, this._key, data);
    return pt;
  }

  private async importKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._api.importKey(
      "raw",
      key,
      { name: "AES-GCM" },
      true,
      consts.AEAD_USAGES,
    );
  }
}
