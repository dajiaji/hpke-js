import { ChaCha20Poly1305 } from "@stablelib/chacha20poly1305";

import type { AeadKey } from "../interfaces/aeadKey.ts";

import { Aead } from "../identifiers.ts";

export class Chacha20Poly1305Key implements AeadKey {
  public readonly id: Aead = Aead.Chacha20Poly1305;
  public readonly keySize: number = 32;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;
  private _key: ChaCha20Poly1305;

  public constructor(key: ArrayBuffer) {
    this._key = new ChaCha20Poly1305(new Uint8Array(key));
  }

  public async seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this._seal(iv, data, aad);
  }

  public async open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return await this._open(iv, data, aad);
  }

  private _seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      const ret = this._key.seal(
        new Uint8Array(iv),
        new Uint8Array(data),
        new Uint8Array(aad),
      );
      resolve(ret.buffer);
    });
  }

  private _open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const ret = this._key.open(
        new Uint8Array(iv),
        new Uint8Array(data),
        new Uint8Array(aad),
      );
      if (ret instanceof Uint8Array) {
        resolve(ret.buffer);
      } else {
        reject(new Error("failed to open."));
      }
    });
  }
}
