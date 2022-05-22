import { ChaCha20Poly1305 } from '@stablelib/chacha20poly1305';

import type { AeadKey } from '../interfaces/aeadKey';

import * as consts from '../consts';

export class Chacha20Poly1305Key implements AeadKey {

  private _key: ChaCha20Poly1305;

  public constructor(key: ArrayBuffer) {
    this._key = new ChaCha20Poly1305(new Uint8Array(key));
  }

  public async encrypt(iv: ArrayBuffer, data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    return await this._encrypt(iv, data, aad);
  }

  public async decrypt(iv: ArrayBuffer, data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    return await this._decrypt(iv, data, aad);
  }

  private _encrypt(iv: ArrayBuffer, data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      const ret = this._key.seal(new Uint8Array(iv), new Uint8Array(data), new Uint8Array(aad));
      resolve(ret.buffer);
    });
  }

  private _decrypt(iv: ArrayBuffer, data: ArrayBuffer, aad: ArrayBuffer): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const ret = this._key.open(new Uint8Array(iv), new Uint8Array(data), new Uint8Array(aad));
      if (ret instanceof Uint8Array) {
        resolve(ret.buffer);
      } else {
        reject(new Error('failed to open.'));
      }
    });
  }
}
