import type { AeadKey } from '../interfaces/aeadKey';

import * as consts from '../consts';

export class AesGcmKey implements AeadKey {

  private _key: CryptoKey | ArrayBuffer;
  private _api: SubtleCrypto;

  public constructor(key: ArrayBuffer, api: SubtleCrypto) {
    this._key = key;
    this._api = api;
  }

  public async encrypt(iv: ArrayBuffer, data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    if (this._key instanceof ArrayBuffer) {
      this._key = await this.importKey(this._key);
    }
    const alg = {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aad,
    };
    const ct: ArrayBuffer = await this._api.encrypt(alg, this._key, data);
    return ct;
  }

  public async decrypt(iv: ArrayBuffer, data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    if (this._key instanceof ArrayBuffer) {
      this._key = await this.importKey(this._key);
    }
    const alg = {
      name: 'AES-GCM',
      iv: iv,
      additionalData: aad,
    };
    const pt: ArrayBuffer = await this._api.decrypt(alg, this._key, data);
    return pt;
  }

  private async importKey(key: ArrayBuffer): Promise<CryptoKey> {
    return await this._api.importKey('raw', key, { name: 'AES-GCM' }, true, consts.AEAD_USAGES);
  }
}
