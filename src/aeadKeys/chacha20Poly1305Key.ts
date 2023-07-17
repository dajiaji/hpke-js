import { chacha20_poly1305 } from "npm:@noble/ciphers@0.1.4/chacha";

import { Algorithm } from "../algorithm.ts";
import type { AeadKey } from "../interfaces/aeadKey.ts";
import { AeadId } from "../identifiers.ts";

export class Chacha20Poly1305Key extends Algorithm implements AeadKey {
  public readonly id: AeadId = AeadId.Chacha20Poly1305;
  public readonly keySize: number = 32;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;
  private _key: Uint8Array;

  public constructor(key: ArrayBuffer) {
    super();
    this._key = new Uint8Array(key);
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
      const ret = chacha20_poly1305(
        this._key,
        new Uint8Array(iv),
        new Uint8Array(aad),
      ).encrypt(new Uint8Array(data));
      resolve(ret.buffer);
    });
  }

  private _open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      const ret = chacha20_poly1305(
        this._key,
        new Uint8Array(iv),
        new Uint8Array(aad),
      ).decrypt(new Uint8Array(data));
      resolve(ret.buffer);
    });
  }
}
