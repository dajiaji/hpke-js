// @ts-ignore: for "npm:"
import { chacha20_poly1305 } from "npm:@noble/ciphers@0.1.4/chacha";

import type { AeadEncryptionContext } from "../interfaces/aeadEncryptionContext.ts";
import type { AeadInterface } from "../interfaces/aeadInterface.ts";

import { Algorithm } from "../algorithm.ts";
import { AeadId } from "../identifiers.ts";

export class Chacha20Poly1305Context implements AeadEncryptionContext {
  private _key: Uint8Array;
  private _api: SubtleCrypto;

  public constructor(api: SubtleCrypto, key: ArrayBuffer) {
    this._api = api;
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

/**
 * The ChaCha20Poly1305 AEAD.
 *
 * @remarks
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-ciphers | @noble/ciphers}.
 *
 * The instance of this class can be specified to the
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 * ```ts
 * import { KemId, KdfId, CipherSuite } from "http://deno.land/x/hpke/core/mod.ts";
 * import { Chacha20Poly1305 } from "https://deno.land/x/hpke/x/chach20poly1305/mod.ts";
 * const suite = new CipherSuite({
 *   kem: KemId.DhkemP256HkdfSha256,
 *   kdf: KdfId.HkdfSha256,
 *   aead: new Chacha20Poly1305(),
 * });
 * ```
 */
export class Chacha20Poly1305 extends Algorithm implements AeadInterface {
  public readonly id: AeadId = AeadId.Chacha20Poly1305;
  public readonly keySize: number = 32;
  public readonly nonceSize: number = 12;
  public readonly tagSize: number = 16;

  public createEncryptionContext(key: ArrayBuffer): AeadEncryptionContext {
    return new Chacha20Poly1305Context(this._api as SubtleCrypto, key);
  }
}
