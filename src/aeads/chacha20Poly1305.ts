// @ts-ignore: for "npm:"
import { chacha20poly1305 } from "npm:@noble/ciphers@0.3.0/chacha";

import type { AeadEncryptionContext } from "../interfaces/aeadEncryptionContext.ts";
import type { AeadInterface } from "../interfaces/aeadInterface.ts";

import { AeadId } from "../identifiers.ts";

export class Chacha20Poly1305Context implements AeadEncryptionContext {
  private _key: Uint8Array;

  public constructor(key: ArrayBuffer) {
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
      const ret = chacha20poly1305(
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
      const ret = chacha20poly1305(
        this._key,
        new Uint8Array(iv),
        new Uint8Array(aad),
      ).decrypt(new Uint8Array(data));
      resolve(ret.buffer);
    });
  }
}

/**
 * The ChaCha20Poly1305 for HPKE AEAD implementing {@link AeadInterface}.
 *
 * When using `@hpke/core`, the instance of this class can be specified
 * to the `aead` parameter of {@link CipherSuiteParams} instead of `AeadId.Chacha20Poly1305`
 * as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   CipherSuite,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 * } from "http://deno.land/x/hpke/core/mod.ts";
 * import {
 *   Chacha20Poly1305,
 * } from "https://deno.land/x/hpke/x/chach20poly1305/mod.ts";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Chacha20Poly1305(),
 * });
 * ```
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-ciphers | @noble/ciphers}.
 */
export class Chacha20Poly1305 implements AeadInterface {
  /** AeadId.Chacha20Poly1305 (0x0003) */
  public readonly id: AeadId = AeadId.Chacha20Poly1305;
  /** 32 */
  public readonly keySize: number = 32;
  /** 12 */
  public readonly nonceSize: number = 12;
  /** 16 */
  public readonly tagSize: number = 16;

  public createEncryptionContext(key: ArrayBuffer): AeadEncryptionContext {
    return new Chacha20Poly1305Context(key);
  }
}
