import type {
  AeadEncryptionContext,
  AeadId,
  AeadInterface,
} from "@hpke/common";
import { toArrayBuffer } from "@hpke/common";

import { chacha20poly1305 } from "./chacha/chacha.ts";

export class Chacha20Poly1305Context implements AeadEncryptionContext {
  private _key: Uint8Array;

  public constructor(key: ArrayBufferLike | ArrayBufferView) {
    this._key = new Uint8Array(toArrayBuffer(key));
  }

  // Keep synchronous validation/encryption errors as Promise rejections.
  // deno-lint-ignore require-await
  public async seal(
    iv: ArrayBufferLike | ArrayBufferView,
    data: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    return chacha20poly1305(
      this._key,
      new Uint8Array(toArrayBuffer(iv)),
      new Uint8Array(toArrayBuffer(aad)),
    ).encrypt(new Uint8Array(toArrayBuffer(data))).buffer as ArrayBuffer;
  }

  // Keep synchronous validation/authentication errors as Promise rejections.
  // deno-lint-ignore require-await
  public async open(
    iv: ArrayBufferLike | ArrayBufferView,
    data: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    return chacha20poly1305(
      this._key,
      new Uint8Array(toArrayBuffer(iv)),
      new Uint8Array(toArrayBuffer(aad)),
    ).decrypt(new Uint8Array(toArrayBuffer(data))).buffer as ArrayBuffer;
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
 * } from "@hpke/core";
 * import {
 *   Chacha20Poly1305,
 * } from "@hpke/chacha20poly1305";
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
  public readonly id: AeadId = 0x0003; // AeadId.Chacha20Poly1305
  /** 32 */
  public readonly keySize: number = 32;
  /** 12 */
  public readonly nonceSize: number = 12;
  /** 16 */
  public readonly tagSize: number = 16;

  public createEncryptionContext(
    key: ArrayBufferLike | ArrayBufferView,
  ): AeadEncryptionContext {
    return new Chacha20Poly1305Context(key);
  }
}
