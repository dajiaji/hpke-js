import type {
  AeadInterface,
  KdfInterface,
  KemInterface,
  RecipientContextParams,
  SenderContextParams,
} from "@hpke/common";

import { EMPTY, NativeAlgorithm } from "@hpke/common";

import type { CipherSuiteParams } from "./interfaces/cipherSuiteParams.ts";
import type {
  RecipientContext,
  SenderContext,
} from "./interfaces/encryptionContext.ts";
import type { CipherSuiteSealResponse } from "./interfaces/responses.ts";

import { initSuite } from "./keySchedule.ts";
import { setupRecipient } from "./recipientContext.ts";
import { setupSender } from "./senderContext.ts";

/**
 * The Hybrid Public Key Encryption (HPKE) ciphersuite,
 * which is implemented using only
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 *
 * This is the super class of {@link CipherSuite} and the same as
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuite | @hpke/core#CipherSuite} as follows:
 * which supports only the ciphersuites that can be implemented on the native
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 * Therefore, the following cryptographic algorithms are not supported for now:
 *   - DHKEM(X25519, HKDF-SHA256)
 *   - DHKEM(X448, HKDF-SHA512)
 *   - ChaCha20Poly1305
 *
 * In addtion, the HKDF functions contained in this class can only derive
 * keys of the same length as the `hashSize`.
 *
 * If you want to use the unsupported cryptographic algorithms
 * above or derive keys longer than the `hashSize`,
 * please use {@link CipherSuite}.
 *
 * This class provides following functions:
 *
 * - Creates encryption contexts both for senders and recipients.
 *   - {@link createSenderContext}
 *   - {@link createRecipientContext}
 * - Provides single-shot encryption API.
 *   - {@link seal}
 *   - {@link open}
 *
 * The calling of the constructor of this class is the starting
 * point for HPKE operations for both senders and recipients.
 *
 * @example Use only ciphersuites supported by Web Cryptography API.
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 *   CipherSuite,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 *
 * @example Use a ciphersuite which is currently not supported by Web Cryptography API.
 *
 * ```ts
 * import { Aes128Gcm, HkdfSha256, CipherSuite } from "@hpke/core";
 * // Use an extension module.
 * import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class CipherSuiteNative extends NativeAlgorithm {
  protected _kem: KemInterface;
  private _kdf: KdfInterface;
  private _aead: AeadInterface;

  /**
   * @param params A set of parameters for building a cipher suite.
   *
   * If the error occurred, throws {@link InvalidParamError}.
   *
   * @throws {@link InvalidParamError}
   */
  constructor(params: CipherSuiteParams) {
    super();
    const suite = initSuite(params);
    this._kem = suite.kem;
    this._kdf = suite.kdf;
    this._aead = suite.aead;
  }

  /**
   * Gets the KEM context of the ciphersuite.
   */
  public get kem(): KemInterface {
    return this._kem;
  }

  /**
   * Gets the KDF context of the ciphersuite.
   */
  public get kdf(): KdfInterface {
    return this._kdf;
  }

  /**
   * Gets the AEAD context of the ciphersuite.
   */
  public get aead(): AeadInterface {
    return this._aead;
  }

  /**
   * Creates an encryption context for a sender.
   *
   * If the error occurred, throws {@link DecapError} | {@link ValidationError}.
   *
   * @param params A set of parameters for the sender encryption context.
   * @returns A sender encryption context.
   * @throws {@link NotSupportedError} if the KEM does not support authentication.
   * @throws {@link EncapError}, {@link ValidationError}
   */
  public async createSenderContext(
    params: SenderContextParams,
  ): Promise<SenderContext> {
    await this._setup();
    // The sender-specific logic lives in senderContext.ts.
    return await setupSender(this, params);
  }

  /**
   * Creates an encryption context for a recipient.
   *
   * If the error occurred, throws {@link DecapError}
   * | {@link DeserializeError} | {@link ValidationError}.
   *
   * @param params A set of parameters for the recipient encryption context.
   * @returns A recipient encryption context.
   * @throws {@link NotSupportedError} if the KEM does not support authentication.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link ValidationError}
   */
  public async createRecipientContext(
    params: RecipientContextParams,
  ): Promise<RecipientContext> {
    await this._setup();
    // The recipient-specific logic lives in recipientContext.ts.
    return await setupRecipient(this, params);
  }

  /**
   * Encrypts a message to a recipient.
   *
   * If the error occurred, throws `EncapError` | `MessageLimitReachedError` | `SealError` | `ValidationError`.
   *
   * @param params A set of parameters for building a sender encryption context.
   * @param pt A plain text as bytes to be encrypted.
   * @param aad Additional authenticated data as bytes fed by an application.
   * @returns A cipher text and an encapsulated key as bytes.
   * @throws {@link EncapError}, {@link MessageLimitReachedError}, {@link SealError}, {@link ValidationError}
   */
  public async seal(
    params: SenderContextParams,
    pt: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView = EMPTY.buffer as ArrayBuffer,
  ): Promise<CipherSuiteSealResponse> {
    const ctx = await this.createSenderContext(params);
    return {
      ct: await ctx.seal(pt, aad),
      enc: ctx.enc,
    };
  }

  /**
   * Decrypts a message from a sender.
   *
   * If the error occurred, throws `DecapError` | `DeserializeError` | `OpenError` | `ValidationError`.
   *
   * @param params A set of parameters for building a recipient encryption context.
   * @param ct An encrypted text as bytes to be decrypted.
   * @param aad Additional authenticated data as bytes fed by an application.
   * @returns A decrypted plain text as bytes.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link OpenError}, {@link ValidationError}
   */
  public async open(
    params: RecipientContextParams,
    ct: ArrayBufferLike | ArrayBufferView,
    aad: ArrayBufferLike | ArrayBufferView = EMPTY.buffer as ArrayBuffer,
  ): Promise<ArrayBuffer> {
    const ctx = await this.createRecipientContext(params);
    return await ctx.open(ct, aad);
  }
}
