import type { AeadInterface } from "./interfaces/aeadInterface.ts";
import type { AeadParams } from "./interfaces/aeadParams.ts";
import type { CipherSuiteParams } from "./interfaces/cipherSuiteParams.ts";
import type { KdfInterface } from "./interfaces/kdfInterface.ts";
import type { KemInterface } from "./interfaces/kemInterface.ts";
import type { KeyScheduleParams } from "./interfaces/keyScheduleParams.ts";
import type { CipherSuiteSealResponse } from "./interfaces/responses.ts";
import type { RecipientContextParams } from "./interfaces/recipientContextParams.ts";
import type { SenderContextParams } from "./interfaces/senderContextParams.ts";
import type {
  RecipientContextInterface,
  SenderContextInterface,
} from "./interfaces/encryptionContextInterface.ts";

import {
  RecipientExporterContext,
  SenderExporterContext,
} from "./exporterContext.ts";
import { AeadId, KdfId, KemId, Mode } from "./identifiers.ts";
import { Aes128Gcm, Aes256Gcm } from "./aeads/aesGcm.ts";
import { ExportOnly } from "./aeads/exportOnly.ts";
import {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "./kdfs/hkdf.ts";
import { RecipientContext } from "./recipientContext.ts";
import { SenderContext } from "./senderContext.ts";
import { loadSubtleCrypto } from "./webCrypto.ts";
import {
  DhkemP256HkdfSha256Native,
  DhkemP384HkdfSha384Native,
  DhkemP521HkdfSha512Native,
} from "./kems/dhkemNative.ts";
import { i2Osp } from "./utils/misc.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

/**
 * The class of Hybrid Public Key Encryption (HPKE) ciphersuite.
 * The calling of the constructor of this class is the starting
 * point for HPKE operations for both senders and recipients.
 *
 * This class supports only the ciphersuites which are
 * supported by the native Web Cryptography API. Therefore,
 * the following cryptographic algorithms are not supported for now:
 *   - DHKEM(X25519, HKDF-SHA256)
 *   - DHKEM(X448, HKDF-SHA512)
 *   - ChaCha20/Poly1305
 *
 * In addtion, the HKDF functions contained in this `CipherSuiteNative`
 * class can only derive keys of the same length as the `hashSize`.
 *
 * Therefore, if you want to use the unsupported cryptographic algorithms
 * above or derive keys longer than the `hashSize`,
 * please use {@link CipherSuite}
 *
 * This class provides following functions:
 *
 * - Generates a key pair for the cipher suite.
 * - Derives a key pair for the cipher suite.
 * - Imports and converts a key to a CryptoKey.
 * - Creates an encryption context both for senders and recipients.
 * - Encrypts a message as a single-shot API.
 * - Decrypts an encrypted message as as single-shot API.
 */
export class CipherSuiteNative {
  private _api: SubtleCrypto | undefined = undefined;
  private _kem: KemInterface;
  private _kdf: KdfInterface;
  private _aead: AeadInterface;
  private _suiteId: Uint8Array;

  /**
   * @param params A set of parameters for building a cipher suite.
   *
   * If the error occurred, throws `InvalidParamError`.
   *
   * @throws {@link InvalidParamError}
   */
  constructor(params: CipherSuiteParams) {
    // KEM
    if (typeof params.kem !== "number") {
      this._kem = params.kem;
    } else {
      switch (params.kem) {
        case KemId.DhkemP256HkdfSha256:
          this._kem = new DhkemP256HkdfSha256Native();
          break;
        case KemId.DhkemP384HkdfSha384:
          this._kem = new DhkemP384HkdfSha384Native();
          break;
        case KemId.DhkemP521HkdfSha512:
          this._kem = new DhkemP521HkdfSha512Native();
          break;
        default:
          throw new errors.InvalidParamError(
            `The KEM (${params.kem}) cannot be specified by KemId. Use submodule for the KEM`,
          );
      }
    }

    // KDF
    if (typeof params.kdf !== "number") {
      this._kdf = params.kdf;
    } else {
      switch (params.kdf) {
        case KdfId.HkdfSha256:
          this._kdf = new HkdfSha256Native();
          break;
        case KdfId.HkdfSha384:
          this._kdf = new HkdfSha384Native();
          break;
        default:
          // case KdfId.HkdfSha512:
          this._kdf = new HkdfSha512Native();
          break;
      }
    }

    // AEAD
    if (typeof params.aead !== "number") {
      this._aead = params.aead;
    } else {
      switch (params.aead) {
        case AeadId.Aes128Gcm:
          this._aead = new Aes128Gcm();
          break;
        case AeadId.Aes256Gcm:
          this._aead = new Aes256Gcm();
          break;
        case AeadId.ExportOnly:
          this._aead = new ExportOnly();
          break;
        default:
          throw new errors.InvalidParamError(
            `The AEAD (${params.aead}) cannot be specified by AeadId. Use submodule for the AEAD`,
          );
      }
    }

    this._suiteId = new Uint8Array(consts.SUITE_ID_HEADER_HPKE);
    this._suiteId.set(i2Osp(this._kem.id, 2), 4);
    this._suiteId.set(i2Osp(this._kdf.id, 2), 6);
    this._suiteId.set(i2Osp(this._aead.id, 2), 8);
  }

  /**
   * Gets the KEM context of the ciphersuite.
   */
  public get kem() {
    return this._kem;
  }

  /**
   * Gets the KDF context of the ciphersuite.
   */
  public get kdf() {
    return this._kdf;
  }

  /**
   * Gets the AEAD context of the ciphersuite.
   */
  public get aead() {
    return this._aead;
  }

  /**
   * Generates a key pair for the cipher suite.
   *
   * @returns A key pair generated.
   */
  public async generateKeyPair(): Promise<CryptoKeyPair> {
    await this._setup();
    return await (this._kem as KemInterface).generateKeyPair();
  }

  /**
   * Derives a key pair for the cipher suite in the manner
   * defined in [RFC9180 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3).
   *
   * If the error occurred, throws `DeriveKeyPairError`.
   *
   * @param ikm A byte string of input keying material. The maximum length is 128 bytes.
   * @returns A key pair derived.
   * @throws {@link DeriveKeyPairError}
   */
  public async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    if (ikm.byteLength > consts.INPUT_LENGTH_LIMIT) {
      throw new errors.InvalidParamError("Too long ikm");
    }
    await this._setup();
    return await (this._kem as KemInterface).deriveKeyPair(ikm);
  }

  /**
   * Imports a public or private key and converts to a CryptoKey
   * which can be used on `createSenderContext` or `createRecipientContext`.
   * Basically, this is a thin wrapper function of
   * [SubtleCrypto.importKey](https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto-method-importKey).
   *
   * If the error occurred, throws `DeserializeError`.
   *
   * NOTE: Currently, EC keys (P-256, P-384 and P-521) are supported on Deno environment.
   *
   * @param format For now, `'raw'` is only supported.
   * @param key A byte string of a raw key.
   * @param isPublic The indicator whether the provided key is a public key or not, which is used only for `'raw'` format.
   * @returns A public or private CryptoKey.
   * @throws {@link DeserializeError}
   */
  public async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic = true,
  ): Promise<CryptoKey> {
    await this._setup();
    return await (this._kem as KemInterface).importKey(format, key, isPublic);
  }

  /**
   * Creates an encryption context for a sender.
   *
   * If the error occurred, throws `EncapError` | `ValidationError`.
   *
   * @param params A set of parameters for the sender encryption context.
   * @returns A sender encryption context.
   * @throws {@link EncapError}, {@link ValidationError}
   */
  public async createSenderContext(
    params: SenderContextParams,
  ): Promise<SenderContextInterface> {
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
   * If the error occurred, throws `DecapError` | `DeserializeError` | `ValidationError`.
   *
   * @param params A set of parameters for the recipient encryption context.
   * @returns A recipient encryption context.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link ValidationError}
   */
  public async createRecipientContext(
    params: RecipientContextParams,
  ): Promise<RecipientContextInterface> {
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
    aad: ArrayBuffer = consts.EMPTY,
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
    aad: ArrayBuffer = consts.EMPTY,
  ): Promise<ArrayBuffer> {
    const ctx = await this.createRecipientContext(params);
    return await ctx.open(ct, aad);
  }

  private async _setup() {
    if (this._api !== undefined) {
      return;
    }
    const api = await loadSubtleCrypto();
    this._kem.init(api as SubtleCrypto);
    this._kdf.init(api as SubtleCrypto, this._suiteId);
    this._aead.init(api as SubtleCrypto);
    this._api = api;
    return;
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
      ? consts.EMPTY
      : new Uint8Array(params.psk.id);
    const pskIdHash = await this._kdf.labeledExtract(
      consts.EMPTY,
      consts.LABEL_PSK_ID_HASH,
      pskId,
    );

    const info = params.info === undefined
      ? consts.EMPTY
      : new Uint8Array(params.info);
    const infoHash = await this._kdf.labeledExtract(
      consts.EMPTY,
      consts.LABEL_INFO_HASH,
      info,
    );

    const keyScheduleContext = new Uint8Array(
      1 + pskIdHash.byteLength + infoHash.byteLength,
    );
    keyScheduleContext.set(new Uint8Array([mode]), 0);
    keyScheduleContext.set(new Uint8Array(pskIdHash), 1);
    keyScheduleContext.set(new Uint8Array(infoHash), 1 + pskIdHash.byteLength);

    const psk = params.psk === undefined
      ? consts.EMPTY
      : new Uint8Array(params.psk.key);
    const ikm = this._kdf.buildLabeledIkm(consts.LABEL_SECRET, psk);

    const exporterSecretInfo = this._kdf.buildLabeledInfo(
      consts.LABEL_EXP,
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
      consts.LABEL_KEY,
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
      consts.LABEL_BASE_NONCE,
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
  ): Promise<SenderContextInterface> {
    const res = await this._keySchedule(mode, sharedSecret, params);
    if (res.key === undefined) {
      return new SenderExporterContext(
        this._api as SubtleCrypto,
        this._kdf,
        res.exporterSecret,
        enc,
      );
    }
    return new SenderContext(
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
  ): Promise<RecipientContextInterface> {
    const res = await this._keySchedule(mode, sharedSecret, params);
    if (res.key === undefined) {
      return new RecipientExporterContext(
        this._api as SubtleCrypto,
        this._kdf,
        res.exporterSecret,
      );
    }
    return new RecipientContext(this._api as SubtleCrypto, this._kdf, res);
  }

  private _validateInputLength(params: KeyScheduleParams) {
    if (
      params.info !== undefined &&
      params.info.byteLength > consts.INPUT_LENGTH_LIMIT
    ) {
      throw new errors.InvalidParamError("Too long info");
    }
    if (params.psk !== undefined) {
      if (params.psk.key.byteLength < consts.MINIMUM_PSK_LENGTH) {
        throw new errors.InvalidParamError(
          `PSK must have at least ${consts.MINIMUM_PSK_LENGTH} bytes`,
        );
      }
      if (params.psk.key.byteLength > consts.INPUT_LENGTH_LIMIT) {
        throw new errors.InvalidParamError("Too long psk.key");
      }
      if (params.psk.id.byteLength > consts.INPUT_LENGTH_LIMIT) {
        throw new errors.InvalidParamError("Too long psk.id");
      }
    }
    return;
  }
}
