import type {
  AeadEncryptionContext,
  AeadId,
  AeadInterface,
} from "@hpke/common";

import { keyWords, open, seal } from "./chacha/chacha.ts";

type Bytes = ArrayBufferLike | ArrayBufferView;

// A plain Uint8Array view without copying. The inputs are only read, and only
// synchronously, so they cannot change underneath seal()/open().
const u8 = (x: Bytes): Uint8Array =>
  ArrayBuffer.isView(x)
    ? new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
    : new Uint8Array(x);

export class Chacha20Poly1305Context implements AeadEncryptionContext {
  // The key as little-endian words; empty if the given key is not 32 bytes,
  // which seal()/open() report as a rejected Promise.
  private _key: Uint32Array;

  public constructor(key: Bytes) {
    this._key = keyWords(u8(key));
  }

  // Keep synchronous validation/encryption errors as Promise rejections.
  // deno-lint-ignore require-await
  public async seal(iv: Bytes, data: Bytes, aad: Bytes): Promise<ArrayBuffer> {
    return seal(this._key, u8(iv), u8(aad), u8(data)).buffer as ArrayBuffer;
  }

  // Keep synchronous validation/authentication errors as Promise rejections.
  // deno-lint-ignore require-await
  public async open(iv: Bytes, data: Bytes, aad: Bytes): Promise<ArrayBuffer> {
    return open(this._key, u8(iv), u8(aad), u8(data)).buffer as ArrayBuffer;
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
 * The implementation is derived from
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
