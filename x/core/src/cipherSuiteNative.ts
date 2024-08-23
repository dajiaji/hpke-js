import type { AeadInterface } from "./interfaces/aeadInterface.ts";
import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { CipherSuiteParams } from "./interfaces/cipherSuiteParams.ts";
import type {
  RecipientContext,
  SenderContext,
} from "./interfaces/encryptionContext.ts";
import type { KdfInterface } from "./interfaces/kdfInterface.ts";
import type { KemInterface } from "./interfaces/kemInterface.ts";
import type { KeyScheduleParams } from "./interfaces/keyScheduleParams.ts";
import type { RecipientContextParams } from "./interfaces/recipientContextParams.ts";
import type { CipherSuiteSealResponse } from "./interfaces/responses.ts";
import type { SenderContextParams } from "./interfaces/senderContextParams.ts";

import { NativeAlgorithm } from "./algorithm.ts";
import { EMPTY, INPUT_LENGTH_LIMIT, MINIMUM_PSK_LENGTH } from "./consts.ts";
import { InvalidParamError } from "./errors.ts";
import {
  RecipientExporterContextImpl,
  SenderExporterContextImpl,
} from "./exporterContext.ts";
import { AeadId, Mode } from "./identifiers.ts";
import { RecipientContextImpl } from "./recipientContext.ts";
import { SenderContextImpl } from "./senderContext.ts";
import { i2Osp } from "./utils/misc.ts";

// b"base_nonce"
// deno-fmt-ignore
const LABEL_BASE_NONCE = new Uint8Array([
  98, 97, 115, 101, 95, 110, 111, 110, 99, 101,
]);
// b"exp"
const LABEL_EXP = new Uint8Array([101, 120, 112]);
// b"info_hash"
// deno-fmt-ignore
const LABEL_INFO_HASH = new Uint8Array([
  105, 110, 102, 111, 95, 104, 97, 115, 104,
]);
// b"key"
const LABEL_KEY = new Uint8Array([107, 101, 121]);
// b"psk_id_hash"
// deno-fmt-ignore
const LABEL_PSK_ID_HASH = new Uint8Array([
  112, 115, 107, 95, 105, 100, 95, 104, 97, 115, 104,
]);
// b"secret"
const LABEL_SECRET = new Uint8Array([115, 101, 99, 114, 101, 116]);
// b"HPKE"
// deno-fmt-ignore
const SUITE_ID_HEADER_HPKE = new Uint8Array([
  72, 80, 75, 69, 0, 0, 0, 0, 0, 0,
]);

/**
 * The Hybrid Public Key Encryption (HPKE) ciphersuite,
 * which is implemented using only
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 *
 * This is the super class of {@link CipherSuite} and the same as
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuite | @hpke/core#CipherSuite },
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
  private _suiteId: Uint8Array;

  /**
   * @param params A set of parameters for building a cipher suite.
   *
   * If the error occurred, throws {@link InvalidParamError}.
   *
   * @throws {@link InvalidParamError}
   */
  constructor(params: CipherSuiteParams) {
    super();

    // KEM
    if (typeof params.kem === "number") {
      throw new InvalidParamError("KemId cannot be used");
    }
    this._kem = params.kem;

    // KDF
    if (typeof params.kdf === "number") {
      throw new InvalidParamError("KdfId cannot be used");
    }
    this._kdf = params.kdf;

    // AEAD
    if (typeof params.aead === "number") {
      throw new InvalidParamError("AeadId cannot be used");
    }
    this._aead = params.aead;

    this._suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
    this._suiteId.set(i2Osp(this._kem.id, 2), 4);
    this._suiteId.set(i2Osp(this._kdf.id, 2), 6);
    this._suiteId.set(i2Osp(this._aead.id, 2), 8);
    this._kdf.init(this._suiteId);
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
   * @throws {@link EncapError}, {@link ValidationError}
   */
  public async createSenderContext(
    params: SenderContextParams,
  ): Promise<SenderContext> {
    this._validateInputLength(params);

    await this._setup();

    const dh = await (this._kem as KemInterface).encap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== undefined ? Mode.Auth : Mode.Base;
    }
    return await this._keyScheduleS(mode, dh.sharedSecret, dh.enc, params);
  }

  /**
   * Creates an encryption context for a recipient.
   *
   * If the error occurred, throws {@link DecapError}
   * | {@link DeserializeError} | {@link ValidationError}.
   *
   * @param params A set of parameters for the recipient encryption context.
   * @returns A recipient encryption context.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link ValidationError}
   */
  public async createRecipientContext(
    params: RecipientContextParams,
  ): Promise<RecipientContext> {
    this._validateInputLength(params);

    await this._setup();

    const sharedSecret = await (this._kem as KemInterface).decap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderPublicKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== undefined ? Mode.Auth : Mode.Base;
    }
    return await this._keyScheduleR(mode, sharedSecret, params);
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
    pt: ArrayBuffer,
    aad: ArrayBuffer = EMPTY,
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
    ct: ArrayBuffer,
    aad: ArrayBuffer = EMPTY,
  ): Promise<ArrayBuffer> {
    const ctx = await this.createRecipientContext(params);
    return await ctx.open(ct, aad);
  }

  // private verifyPskInputs(mode: Mode, params: KeyScheduleParams) {
  //   const gotPsk = (params.psk !== undefined);
  //   const gotPskId = (params.psk !== undefined && params.psk.id.byteLength > 0);
  //   if (gotPsk !== gotPskId) {
  //     throw new Error('Inconsistent PSK inputs');
  //   }
  //   if (gotPsk && (mode === Mode.Base || mode === Mode.Auth)) {
  //     throw new Error('PSK input provided when not needed');
  //   }
  //   if (!gotPsk && (mode === Mode.Psk || mode === Mode.AuthPsk)) {
  //     throw new Error('Missing required PSK input');
  //   }
  //   return;
  // }

  private async _keySchedule(
    mode: Mode,
    sharedSecret: ArrayBuffer,
    params: KeyScheduleParams,
  ): Promise<AeadParams> {
    // Currently, there is no point in executing this function
    // because this hpke library does not allow users to explicitly specify the mode.
    //
    // this.verifyPskInputs(mode, params);

    const pskId = params.psk === undefined
      ? EMPTY
      : new Uint8Array(params.psk.id);
    const pskIdHash = await this._kdf.labeledExtract(
      EMPTY,
      LABEL_PSK_ID_HASH,
      pskId,
    );

    const info = params.info === undefined
      ? EMPTY
      : new Uint8Array(params.info);
    const infoHash = await this._kdf.labeledExtract(
      EMPTY,
      LABEL_INFO_HASH,
      info,
    );

    const keyScheduleContext = new Uint8Array(
      1 + pskIdHash.byteLength + infoHash.byteLength,
    );
    keyScheduleContext.set(new Uint8Array([mode]), 0);
    keyScheduleContext.set(new Uint8Array(pskIdHash), 1);
    keyScheduleContext.set(new Uint8Array(infoHash), 1 + pskIdHash.byteLength);

    const psk = params.psk === undefined
      ? EMPTY
      : new Uint8Array(params.psk.key);
    const ikm = this._kdf.buildLabeledIkm(LABEL_SECRET, psk);

    const exporterSecretInfo = this._kdf.buildLabeledInfo(
      LABEL_EXP,
      keyScheduleContext,
      this._kdf.hashSize,
    );
    const exporterSecret = await this._kdf.extractAndExpand(
      sharedSecret,
      ikm,
      exporterSecretInfo,
      this._kdf.hashSize,
    );

    if (this._aead.id === AeadId.ExportOnly) {
      return { aead: this._aead, exporterSecret: exporterSecret };
    }

    const keyInfo = this._kdf.buildLabeledInfo(
      LABEL_KEY,
      keyScheduleContext,
      this._aead.keySize,
    );
    const key = await this._kdf.extractAndExpand(
      sharedSecret,
      ikm,
      keyInfo,
      this._aead.keySize,
    );

    const baseNonceInfo = this._kdf.buildLabeledInfo(
      LABEL_BASE_NONCE,
      keyScheduleContext,
      this._aead.nonceSize,
    );
    const baseNonce = await this._kdf.extractAndExpand(
      sharedSecret,
      ikm,
      baseNonceInfo,
      this._aead.nonceSize,
    );

    return {
      aead: this._aead,
      exporterSecret: exporterSecret,
      key: key,
      baseNonce: new Uint8Array(baseNonce),
      seq: 0,
    };
  }

  private async _keyScheduleS(
    mode: Mode,
    sharedSecret: ArrayBuffer,
    enc: ArrayBuffer,
    params: KeyScheduleParams,
  ): Promise<SenderContext> {
    const res = await this._keySchedule(mode, sharedSecret, params);
    if (res.key === undefined) {
      return new SenderExporterContextImpl(
        this._api as SubtleCrypto,
        this._kdf,
        res.exporterSecret,
        enc,
      );
    }
    return new SenderContextImpl(
      this._api as SubtleCrypto,
      this._kdf,
      res,
      enc,
    );
  }

  private async _keyScheduleR(
    mode: Mode,
    sharedSecret: ArrayBuffer,
    params: KeyScheduleParams,
  ): Promise<RecipientContext> {
    const res = await this._keySchedule(mode, sharedSecret, params);
    if (res.key === undefined) {
      return new RecipientExporterContextImpl(
        this._api as SubtleCrypto,
        this._kdf,
        res.exporterSecret,
      );
    }
    return new RecipientContextImpl(this._api as SubtleCrypto, this._kdf, res);
  }

  private _validateInputLength(params: KeyScheduleParams) {
    if (
      params.info !== undefined &&
      params.info.byteLength > INPUT_LENGTH_LIMIT
    ) {
      throw new InvalidParamError("Too long info");
    }
    if (params.psk !== undefined) {
      if (params.psk.key.byteLength < MINIMUM_PSK_LENGTH) {
        throw new InvalidParamError(
          `PSK must have at least ${MINIMUM_PSK_LENGTH} bytes`,
        );
      }
      if (params.psk.key.byteLength > INPUT_LENGTH_LIMIT) {
        throw new InvalidParamError("Too long psk.key");
      }
      if (params.psk.id.byteLength > INPUT_LENGTH_LIMIT) {
        throw new InvalidParamError("Too long psk.id");
      }
    }
    return;
  }
}
