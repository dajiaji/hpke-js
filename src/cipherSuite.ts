import type { CipherSuiteParams } from "./interfaces/cipherSuiteParams.ts";
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
import { Aead, Kdf, Kem, Mode } from "./identifiers.ts";
import { KdfContext } from "./kdfContext.ts";
import { KemContext } from "./kemContext.ts";
import { RecipientContext } from "./recipientContext.ts";
import { SenderContext } from "./senderContext.ts";
import { loadSubtleCrypto } from "./webCrypto.ts";

import * as consts from "./consts.ts";
import * as errors from "./errors.ts";

/**
 * The class of Hybrid Public Key Encryption (HPKE) cipher suite
 * which provides following functions:
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

  private _ctx: CipherSuiteParams;
  private _kem: KemContext | undefined = undefined;
  private _kdf: KdfContext | undefined = undefined;

  /**
   * @param params A set of parameters for building a cipher suite.
   * @throws {@link InvalidParamError}
   */
  constructor(params: CipherSuiteParams) {
    switch (params.kem) {
      case Kem.DhkemP256HkdfSha256:
      case Kem.DhkemP384HkdfSha384:
      case Kem.DhkemP521HkdfSha512:
      case Kem.DhkemX25519HkdfSha256:
      case Kem.DhkemX448HkdfSha512:
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
      case Aead.Aes256Gcm:
      case Aead.Chacha20Poly1305:
      case Aead.ExportOnly:
        break;
      default:
        throw new errors.InvalidParamError("Invalid AEAD id");
    }
    this.aead = params.aead;
    this._ctx = { kem: this.kem, kdf: this.kdf, aead: this.aead };
    return;
  }

  /**
   * Generates a key pair for the cipher suite.
   *
   * @returns A key pair generated.
   */
  public async generateKeyPair(): Promise<CryptoKeyPair> {
    await this.setup();
    return await (this._kem as KemContext).generateKeyPair();
  }

  /**
   * Derives a key pair for the cipher suite in the manner
   * defined in [RFC9180 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3).
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
    return await (this._kem as KemContext).deriveKeyPair(ikm);
  }

  /**
   * Imports a public or private key and converts to a CryptoKey
   * which can be used on {@link createSenderContext} or {@link createRecipientContext}.
   * Basically, this is a thin wrapper function of
   * [SubtleCrypto.importKey](https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto-method-importKey).
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
    return await (this._kem as KemContext).importKey(format, key, isPublic);
  }

  /**
   * Creates an encryption context for a sender.
   *
   * @param params A set of parameters for the sender encryption context.
   * @returns A sender encryption context.
   * @throws {@link EncapError}, {@link ValidationError}
   */
  public async createSenderContext(
    params: SenderContextParams,
  ): Promise<SenderContextInterface> {
    this.validateInputLength(params);

    const api = await this.setup();

    const dh = await (this._kem as KemContext).encap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext(api, this._ctx);
    const res = await (this._kdf as KdfContext).keySchedule(
      mode,
      dh.sharedSecret,
      params,
    );
    if (res.key === undefined) {
      return new SenderExporterContext(api, kdf, res.exporterSecret, dh.enc);
    }
    return new SenderContext(api, kdf, res, dh.enc);
  }

  /**
   * Creates an encryption context for a recipient.
   *
   * @param params A set of parameters for the recipient encryption context.
   * @returns A recipient encryption context.
   * @throws {@link DecapError}, {@link DeserializeError}, {@link ValidationError}
   */
  public async createRecipientContext(
    params: RecipientContextParams,
  ): Promise<RecipientContextInterface> {
    this.validateInputLength(params);

    const api = await this.setup();

    const sharedSecret = await (this._kem as KemContext).decap(params);

    let mode: Mode;
    if (params.psk !== undefined) {
      mode = params.senderPublicKey !== undefined ? Mode.AuthPsk : Mode.Psk;
    } else {
      mode = params.senderPublicKey !== undefined ? Mode.Auth : Mode.Base;
    }

    const kdf = new KdfContext(api, this._ctx);
    const res = await (this._kdf as KdfContext).keySchedule(
      mode,
      sharedSecret,
      params,
    );
    if (res.key === undefined) {
      return new RecipientExporterContext(api, kdf, res.exporterSecret);
    }
    return new RecipientContext(api, kdf, res);
  }

  /**
   * Encrypts a messege to a recipient.
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
   * Decrypts a messege from a sender.
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

  private async setup(): Promise<SubtleCrypto> {
    const api = await loadSubtleCrypto();
    if (this._kem === undefined || this._kdf === undefined) {
      this._kem = new KemContext(api, this.kem);
      this._kdf = new KdfContext(api, this._ctx);
    }
    return api;
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
}
