import type { AeadKey } from "./interfaces/aeadKey.ts";
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
import { createAeadKey } from "./encryptionContext.ts";
import { Aead, Kdf, Kem, Mode } from "./identifiers.ts";
import { HkdfSha256, HkdfSha384, HkdfSha512 } from "./kdfs/hkdf.ts";
import { RecipientContext } from "./recipientContext.ts";
import { SenderContext } from "./senderContext.ts";
import { loadSubtleCrypto } from "./webCrypto.ts";
import {
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemX25519HkdfSha256,
  DhkemX448HkdfSha512,
} from "./kems/dhkem.ts";
import { i2Osp } from "./utils/misc.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

/**
 * The class of Hybrid Public Key Encryption (HPKE) cipher suite.
 * The calling of the constructor of this class is the starting
 * point for HPKE operations for both senders and recipients.
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
export class CipherSuite {
  /** The KEM id of the cipher suite. */
  public readonly kem: Kem;
  /** The KDF id of the cipher suite. */
  public readonly kdf: Kdf;
  /** The AEAD id of the cipher suite. */
  public readonly aead: Aead;

  /** The length in bytes of a KEM shared secret produced by this KEM (Nsecret). */
  public readonly kemSecretSize: number = 0;
  /** The length in bytes of an encapsulated key produced by this KEM (Nenc). */
  public readonly kemEncSize: number = 0;
  /** The length in bytes of an encoded public key for this KEM (Npk). */
  public readonly kemPublicKeySize: number = 0;
  /** The length in bytes of an encoded private key for this KEM (Nsk). */
  public readonly kemPrivateKeySize: number = 0;
  /** The length in bytes of an AEAD key (Nk). */
  public readonly aeadKeySize: number = 0;
  /** The length in bytes of an AEAD nonce (Nn). */
  public readonly aeadNonceSize: number = 0;
  /** The length in bytes of an AEAD authentication tag (Nt). */
  public readonly aeadTagSize: number = 0;

  private _api: SubtleCrypto | undefined = undefined;
  private _kem: KemInterface | undefined = undefined;
  private _kdf: KdfInterface | undefined = undefined;
  private _suiteId: Uint8Array;

  /**
   * @param params A set of parameters for building a cipher suite.
   *
   * If the error occurred, throws `InvalidParamError`.
   *
   * @throws {@link InvalidParamError}
   */
  constructor(params: CipherSuiteParams) {
    switch (params.kem) {
      case Kem.DhkemP256HkdfSha256:
        this.kemSecretSize = 32;
        this.kemEncSize = 65;
        this.kemPublicKeySize = 65;
        this.kemPrivateKeySize = 32;
        break;
      case Kem.DhkemP384HkdfSha384:
        this.kemSecretSize = 48;
        this.kemEncSize = 97;
        this.kemPublicKeySize = 97;
        this.kemPrivateKeySize = 48;
        break;
      case Kem.DhkemP521HkdfSha512:
        this.kemSecretSize = 64;
        this.kemEncSize = 133;
        this.kemPublicKeySize = 133;
        this.kemPrivateKeySize = 66;
        break;
      case Kem.DhkemX25519HkdfSha256:
        this.kemSecretSize = 32;
        this.kemEncSize = 32;
        this.kemPublicKeySize = 32;
        this.kemPrivateKeySize = 32;
        break;
      case Kem.DhkemX448HkdfSha512:
        this.kemSecretSize = 64;
        this.kemEncSize = 56;
        this.kemPublicKeySize = 56;
        this.kemPrivateKeySize = 56;
        break;
      default:
        throw new errors.InvalidParamError("Invalid KEM id");
    }
    this.kem = params.kem;

    switch (params.kdf) {
      case Kdf.HkdfSha256:
      case Kdf.HkdfSha384:
      case Kdf.HkdfSha512:
        break;
      default:
        throw new errors.InvalidParamError("Invalid KDF id");
    }
    this.kdf = params.kdf;

    switch (params.aead) {
      case Aead.Aes128Gcm:
        this.aeadKeySize = 16;
        this.aeadNonceSize = 12;
        this.aeadTagSize = 16;
        break;
      case Aead.Aes256Gcm:
        this.aeadKeySize = 32;
        this.aeadNonceSize = 12;
        this.aeadTagSize = 16;
        break;
      case Aead.Chacha20Poly1305:
        this.aeadKeySize = 32;
        this.aeadNonceSize = 12;
        this.aeadTagSize = 16;
        break;
      case Aead.ExportOnly:
        break;
      default:
        throw new errors.InvalidParamError("Invalid AEAD id");
    }
    this.aead = params.aead;
    this._suiteId = new Uint8Array(consts.SUITE_ID_HEADER_HPKE);
    this._suiteId.set(i2Osp(this.kem, 2), 4);
    this._suiteId.set(i2Osp(this.kdf, 2), 6);
    this._suiteId.set(i2Osp(this.aead, 2), 8);
  }

  /**
   * Gets a suite-specific KEM context.
   *
   * @returns A KDF context.
   */
  public async kemContext(): Promise<KemInterface> {
    await this.setup();
    return this._kem as KemInterface;
  }

  /**
   * Gets a suite-specific KDF context.
   *
   * @returns A KDF context.
   */
  public async kdfContext(): Promise<KdfInterface> {
    await this.setup();
    return this._kdf as KdfInterface;
  }

  /**
   * Creates a suite-specific AEAD key.
   *
   * @param key A byte string of the raw key.
   *
   * @returns An AEAD key.
   */
  public async createAeadKey(key: ArrayBuffer): Promise<AeadKey> {
    await this.setup();
    return createAeadKey(this.aead, key, this._api as SubtleCrypto);
  }

  /**
   * Generates a key pair for the cipher suite.
   *
   * @returns A key pair generated.
   */
  public async generateKeyPair(): Promise<CryptoKeyPair> {
    await this.setup();
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
    await this.setup();
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
    format: "raw",
    key: ArrayBuffer,
    isPublic = true,
  ): Promise<CryptoKey> {
    await this.setup();
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
    this.validateInputLength(params);

    await this.setup();

    const dh = await (this._kem as KemInterface).encap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== undefined ? Mode.Auth : Mode.Base;
    }
    return await this.keyScheduleS(mode, dh.sharedSecret, dh.enc, params);
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
    this.validateInputLength(params);

    await this.setup();

    const sharedSecret = await (this._kem as KemInterface).decap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderPublicKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== undefined ? Mode.Auth : Mode.Base;
    }
    return await this.keyScheduleR(mode, sharedSecret, params);
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

  private async setup() {
    this._api = await loadSubtleCrypto();
    if (this._kem === undefined || this._kdf === undefined) {
      this._kem = this.createKemContext();
      this._kdf = this.createKdfContext();
    }
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

  private async keySchedule(
    mode: Mode,
    sharedSecret: ArrayBuffer,
    params: KeyScheduleParams,
  ): Promise<{ params: AeadParams; kdf: KdfInterface }> {
    // Currently, there is no point in executing this function
    // because this hpke library does not allow users to explicitly specify the mode.
    //
    // this.verifyPskInputs(mode, params);

    const kdf = this.createKdfContext();

    const pskId = params.psk === undefined
      ? consts.EMPTY
      : new Uint8Array(params.psk.id);
    const pskIdHash = await kdf.labeledExtract(
      consts.EMPTY,
      consts.LABEL_PSK_ID_HASH,
      pskId,
    );

    const info = params.info === undefined
      ? consts.EMPTY
      : new Uint8Array(params.info);
    const infoHash = await kdf.labeledExtract(
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
    const ikm = kdf.buildLabeledIkm(consts.LABEL_SECRET, psk);

    const exporterSecretInfo = kdf.buildLabeledInfo(
      consts.LABEL_EXP,
      keyScheduleContext,
      kdf.hashSize,
    );
    const exporterSecret = await kdf.extractAndExpand(
      sharedSecret,
      ikm,
      exporterSecretInfo,
      kdf.hashSize,
    );

    if (this.aead === Aead.ExportOnly) {
      return {
        params: {
          aead: this.aead,
          exporterSecret: exporterSecret,
        },
        kdf: kdf,
      };
    }

    const keyInfo = kdf.buildLabeledInfo(
      consts.LABEL_KEY,
      keyScheduleContext,
      this.aeadKeySize,
    );
    const key = await kdf.extractAndExpand(
      sharedSecret,
      ikm,
      keyInfo,
      this.aeadKeySize,
    );

    const baseNonceInfo = kdf.buildLabeledInfo(
      consts.LABEL_BASE_NONCE,
      keyScheduleContext,
      this.aeadNonceSize,
    );
    const baseNonce = await kdf.extractAndExpand(
      sharedSecret,
      ikm,
      baseNonceInfo,
      this.aeadNonceSize,
    );

    return {
      params: {
        aead: this.aead,
        exporterSecret: exporterSecret,
        key: key,
        baseNonce: new Uint8Array(baseNonce),
        seq: 0,
      },
      kdf: kdf,
    };
  }

  private async keyScheduleS(
    mode: Mode,
    sharedSecret: ArrayBuffer,
    enc: ArrayBuffer,
    params: KeyScheduleParams,
  ): Promise<SenderContextInterface> {
    const res = await this.keySchedule(mode, sharedSecret, params);
    if (res.params.key === undefined) {
      return new SenderExporterContext(
        this._api as SubtleCrypto,
        res.kdf,
        res.params.exporterSecret,
        enc,
      );
    }
    return new SenderContext(
      this._api as SubtleCrypto,
      res.kdf,
      res.params,
      enc,
    );
  }

  private async keyScheduleR(
    mode: Mode,
    sharedSecret: ArrayBuffer,
    params: KeyScheduleParams,
  ): Promise<RecipientContextInterface> {
    const res = await this.keySchedule(mode, sharedSecret, params);
    if (res.params.key === undefined) {
      return new RecipientExporterContext(
        this._api as SubtleCrypto,
        res.kdf,
        res.params.exporterSecret,
      );
    }
    return new RecipientContext(this._api as SubtleCrypto, res.kdf, res.params);
  }

  private validateInputLength(params: KeyScheduleParams) {
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

  private createKemContext(): KemInterface {
    switch (this.kem) {
      case Kem.DhkemP256HkdfSha256:
        return new DhkemP256HkdfSha256(this._api as SubtleCrypto);
      case Kem.DhkemP384HkdfSha384:
        return new DhkemP384HkdfSha384(this._api as SubtleCrypto);
      case Kem.DhkemP521HkdfSha512:
        return new DhkemP521HkdfSha512(this._api as SubtleCrypto);
      case Kem.DhkemX25519HkdfSha256:
        return new DhkemX25519HkdfSha256(this._api as SubtleCrypto);
      default:
        // case Kem.DhkemX448HkdfSha512:
        return new DhkemX448HkdfSha512(this._api as SubtleCrypto);
    }
  }

  private createKdfContext(): KdfInterface {
    switch (this.kdf) {
      case Kdf.HkdfSha256:
        return new HkdfSha256(this._api as SubtleCrypto, this._suiteId);
      case Kdf.HkdfSha384:
        return new HkdfSha384(this._api as SubtleCrypto, this._suiteId);
      default:
        // case Kdf.HkdfSha512:
        return new HkdfSha512(this._api as SubtleCrypto, this._suiteId);
    }
  }
}
