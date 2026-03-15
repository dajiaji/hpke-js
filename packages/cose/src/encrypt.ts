import type { CipherSuite } from "@hpke/core";

import { encode, encodeTagged } from "./cbor/encoder.ts";
import { decode } from "./cbor/decoder.ts";
import type { CborValue } from "./cbor/types.ts";
import {
  type ContentAlg,
  contentKeySize,
  contentNonceSize,
  type CoseHpkeAlg,
  isKeyEncryption,
} from "./alg.ts";
import { CoseError } from "./errors.ts";
import { extractPrivateKeyBytes, extractPublicKeyBytes } from "./coseKey.ts";
import {
  buildEncStructureEncrypt,
  buildRecipientStructure,
  HeaderLabel,
} from "./structures.ts";

const EMPTY = new Uint8Array(0);

function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Content encryption interface for Layer 0.
 * Each factory provides the appropriate implementation
 * (e.g. AES-GCM via WebCrypto, ChaCha20/Poly1305).
 */
export interface ContentCrypto {
  seal(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array>;
  open(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array>;
}

/** A recipient descriptor for CoseEncrypt.seal(). */
export interface CoseRecipient {
  /** The recipient's public key. */
  recipientPublicKey: CryptoKey;
  /** Key identifier for the recipient (bstr per RFC 9052). */
  kid?: Uint8Array;
  /** Extra info embedded in Recipient_structure. */
  extraInfo?: Uint8Array;
  /**
   * HPKE AAD for this recipient (Layer 1).
   * Per draft-ietf-cose-hpke-24, this SHOULD be empty. Only use for
   * special cases where additional authenticated data is needed at the
   * key-wrapping layer. Defaults to empty.
   */
  aad?: Uint8Array;
  /** Pre-shared key for PSK mode. */
  psk?: { id: Uint8Array; key: Uint8Array };
}

/** Options for CoseEncrypt.seal(). */
export interface CoseEncryptSealOptions {
  /** External AAD for Layer 0 content encryption. */
  externalAad?: Uint8Array;
  /** If true, output is wrapped in CBOR Tag 96 (COSE_Encrypt). */
  tagged?: boolean;
}

/** Options for CoseEncrypt.open(). */
export interface CoseEncryptOpenOptions {
  /** External AAD for Layer 0 content decryption. */
  externalAad?: Uint8Array;
  /** Extra info for Recipient_structure. */
  extraInfo?: Uint8Array;
  /**
   * HPKE AAD for this recipient (Layer 1).
   * Per draft-ietf-cose-hpke-24, this SHOULD be empty. Only use for
   * special cases where additional authenticated data is needed at the
   * key-wrapping layer. Defaults to empty.
   */
  aad?: Uint8Array;
  /** Pre-shared key for PSK mode. */
  psk?: { id: Uint8Array; key: Uint8Array };
  /** Key identifier to match against recipient protected headers. */
  kid?: Uint8Array;
  /**
   * Detached ciphertext for open(). When provided, the ciphertext field
   * in the COSE structure (which should be null) is replaced by this value.
   */
  detachedPayload?: Uint8Array;
}

/** Result of a detached seal operation. */
export interface CoseEncryptDetachedResult {
  /** CBOR-encoded COSE_Encrypt with null ciphertext. */
  message: Uint8Array;
  /** The ciphertext transported separately. */
  payload: Uint8Array;
}

/**
 * COSE_Encrypt (Key Encryption) using HPKE.
 *
 * Implements draft-ietf-cose-hpke-24 Section 5 (Key Agreement with Key Wrap).
 */
export interface CoseEncrypt {
  /** The underlying HPKE CipherSuite. */
  readonly suite: CipherSuite;

  /**
   * Generate a KEM key pair.
   */
  generateKemKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Encrypt plaintext into a CBOR-encoded COSE_Encrypt structure.
   */
  seal(
    recipients: CoseRecipient[],
    plaintext: Uint8Array,
    options?: CoseEncryptSealOptions,
  ): Promise<Uint8Array>;

  /**
   * Encrypt plaintext into a detached COSE_Encrypt structure.
   * The ciphertext field is null; the actual payload is returned separately.
   */
  sealDetached(
    recipients: CoseRecipient[],
    plaintext: Uint8Array,
    options?: CoseEncryptSealOptions,
  ): Promise<CoseEncryptDetachedResult>;

  /**
   * Decrypt a CBOR-encoded COSE_Encrypt structure.
   * For detached payloads, pass the ciphertext via options.detachedPayload.
   */
  open(
    recipientKey: CryptoKeyPair | CryptoKey,
    data: Uint8Array,
    options?: CoseEncryptOpenOptions,
  ): Promise<Uint8Array>;

  /**
   * Import a public key from a CBOR-encoded COSE_Key.
   * Validates kty, crv, and key length.
   */
  importPublicCoseKey(coseKeyBytes: Uint8Array): Promise<CryptoKey>;

  /**
   * Import a private key from a CBOR-encoded COSE_Key.
   * Validates kty, crv, and key length.
   */
  importPrivateCoseKey(coseKeyBytes: Uint8Array): Promise<CryptoKey>;
}

/** @internal */
export class CoseEncryptImpl implements CoseEncrypt {
  private _suite: CipherSuite;
  private _alg: CoseHpkeAlg;
  private _contentAlg: ContentAlg;
  private _contentCrypto: ContentCrypto;

  /**
   * @param suite The HPKE CipherSuite to use for key wrapping.
   * @param alg A COSE HPKE algorithm identifier for Key Encryption (46-53).
   * @param contentAlg The content encryption algorithm (A128GCM=1, A256GCM=3, or CHACHA20POLY1305=24).
   * @param contentCrypto Content encryption implementation for Layer 0.
   */
  constructor(
    suite: CipherSuite,
    alg: CoseHpkeAlg,
    contentAlg: ContentAlg,
    contentCrypto: ContentCrypto,
  ) {
    if (!isKeyEncryption(alg)) {
      throw new CoseError(
        `CoseEncrypt requires a Key Encryption algorithm (46-53), got ${alg}`,
      );
    }
    this._suite = suite;
    this._alg = alg;
    this._contentAlg = contentAlg;
    this._contentCrypto = contentCrypto;
  }

  /** The underlying HPKE CipherSuite. */
  get suite(): CipherSuite {
    return this._suite;
  }

  /**
   * Generate a KEM key pair.
   */
  async generateKemKeyPair(): Promise<CryptoKeyPair> {
    return await this._suite.kem.generateKeyPair();
  }

  /**
   * Encrypt plaintext into a CBOR-encoded COSE_Encrypt structure.
   *
   * @param recipients One or more recipient descriptors.
   * @param plaintext The data to encrypt.
   * @param options Optional seal parameters.
   * @returns CBOR-encoded COSE_Encrypt.
   */
  async seal(
    recipients: CoseRecipient[],
    plaintext: Uint8Array,
    options?: CoseEncryptSealOptions,
  ): Promise<Uint8Array> {
    const inner = await this._sealInner(recipients, plaintext, options);
    const coseEncrypt: CborValue[] = [
      inner.protectedHeader,
      inner.unprotectedMap,
      inner.ciphertext,
      inner.recipientEntries,
    ];
    if (options?.tagged) {
      return encodeTagged(96, coseEncrypt);
    }
    return encode(coseEncrypt);
  }

  async sealDetached(
    recipients: CoseRecipient[],
    plaintext: Uint8Array,
    options?: CoseEncryptSealOptions,
  ): Promise<CoseEncryptDetachedResult> {
    const inner = await this._sealInner(recipients, plaintext, options);
    const coseEncrypt: CborValue[] = [
      inner.protectedHeader,
      inner.unprotectedMap,
      null,
      inner.recipientEntries,
    ];
    const message = options?.tagged
      ? encodeTagged(96, coseEncrypt)
      : encode(coseEncrypt);
    return { message, payload: inner.ciphertext };
  }

  private async _sealInner(
    recipients: CoseRecipient[],
    plaintext: Uint8Array,
    options?: CoseEncryptSealOptions,
  ): Promise<{
    protectedHeader: Uint8Array;
    unprotectedMap: Map<CborValue, CborValue>;
    ciphertext: Uint8Array;
    recipientEntries: CborValue[];
  }> {
    if (recipients.length === 0) {
      throw new CoseError("At least one recipient is required");
    }

    const extAad = options?.externalAad ?? EMPTY;
    const keySize = contentKeySize(this._contentAlg);
    const nonceSize = contentNonceSize(this._contentAlg);

    const cek = crypto.getRandomValues(new Uint8Array(keySize));
    const nonce = crypto.getRandomValues(new Uint8Array(nonceSize));

    const protectedMap = new Map<CborValue, CborValue>();
    protectedMap.set(HeaderLabel.ALG, this._contentAlg);
    const protectedHeader = encode(protectedMap);

    const unprotectedMap = new Map<CborValue, CborValue>();
    unprotectedMap.set(HeaderLabel.IV, nonce);

    const aad = buildEncStructureEncrypt(protectedHeader, extAad);
    const ciphertext = await this._contentEncrypt(cek, nonce, plaintext, aad);

    const recipientEntries: CborValue[] = [];
    for (const r of recipients) {
      const entry = await this._wrapCek(r, cek);
      recipientEntries.push(entry);
    }

    return { protectedHeader, unprotectedMap, ciphertext, recipientEntries };
  }

  /**
   * Decrypt a CBOR-encoded COSE_Encrypt structure.
   *
   * @param recipientKey The recipient's key pair or private key.
   * @param data CBOR-encoded COSE_Encrypt.
   * @param options Optional parameters.
   * @returns Decrypted plaintext.
   */
  async open(
    recipientKey: CryptoKeyPair | CryptoKey,
    data: Uint8Array,
    options?: CoseEncryptOpenOptions,
  ): Promise<Uint8Array> {
    const extAad = options?.externalAad ?? EMPTY;
    const extraInfo = options?.extraInfo ?? EMPTY;
    const hpkeAad = options?.aad ?? EMPTY;

    const decoded = decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 4) {
      throw new CoseError("Invalid COSE_Encrypt structure");
    }

    const protectedHeader = decoded[0];
    const unprotectedHeader = decoded[1];
    const rawCiphertext = decoded[2];
    const recipientsList = decoded[3];

    if (!(protectedHeader instanceof Uint8Array)) {
      throw new CoseError("Invalid protected header");
    }

    // Support detached payload: if ciphertext in structure is null,
    // use detachedPayload from options.
    let ciphertext: Uint8Array;
    if (rawCiphertext === null) {
      if (!options?.detachedPayload) {
        throw new CoseError(
          "Ciphertext is null (detached) but no detachedPayload provided",
        );
      }
      ciphertext = options.detachedPayload;
    } else if (rawCiphertext instanceof Uint8Array) {
      ciphertext = rawCiphertext;
    } else {
      throw new CoseError("Invalid ciphertext");
    }

    if (!Array.isArray(recipientsList)) {
      throw new CoseError("Invalid recipients array");
    }

    // Parse Layer 0 protected header
    const headerMap = decode(protectedHeader);
    if (!(headerMap instanceof Map)) {
      throw new CoseError("Protected header is not a map");
    }

    // If alg is present, verify it matches. If absent, proceed with
    // the instance's configured content algorithm (Postel's principle).
    const algValue = headerMap.get(HeaderLabel.ALG);
    if (algValue !== undefined && algValue !== this._contentAlg) {
      throw new CoseError(
        `Content algorithm mismatch: expected ${this._contentAlg}, got ${algValue}`,
      );
    }

    // Read IV from unprotected header
    if (!(unprotectedHeader instanceof Map)) {
      throw new CoseError("Invalid unprotected header");
    }
    const nonce = unprotectedHeader.get(HeaderLabel.IV);
    if (!(nonce instanceof Uint8Array)) {
      throw new CoseError("Missing or invalid IV in unprotected header");
    }

    const privateKey = "privateKey" in recipientKey
      ? (recipientKey as CryptoKeyPair).privateKey
      : recipientKey as CryptoKey;

    // Find matching recipient and unwrap CEK
    let cek: Uint8Array | null = null;

    for (const entry of recipientsList) {
      if (!Array.isArray(entry) || entry.length !== 3) continue;

      const rProtected = entry[0];
      const rUnprotected = entry[1];
      const rCiphertext = entry[2];

      if (!(rProtected instanceof Uint8Array)) continue;
      if (!(rCiphertext instanceof Uint8Array)) continue;

      const rHeader = decode(rProtected);
      if (!(rHeader instanceof Map)) continue;

      // If alg is present in recipient header, verify it matches.
      // If absent, try this recipient (Postel's principle).
      const rAlg = rHeader.get(HeaderLabel.ALG);
      if (rAlg !== undefined && rAlg !== this._alg) continue;

      // Match by kid if specified
      if (options?.kid) {
        const rKid = rHeader.get(HeaderLabel.KID);
        if (!(rKid instanceof Uint8Array)) continue;
        if (!uint8ArrayEqual(rKid, options.kid)) continue;
      }

      // ek is in the unprotected header
      if (!(rUnprotected instanceof Map)) continue;
      const rEnc = rUnprotected.get(HeaderLabel.EK);
      if (!(rEnc instanceof Uint8Array)) continue;

      // Validate psk_id / mode consistency (draft-ietf-cose-hpke §5)
      // psk_id MUST be in the recipient protected header per spec.
      if (options?.psk) {
        const storedPskId = rHeader.get(HeaderLabel.PSK_ID);
        if (!(storedPskId instanceof Uint8Array)) continue;
        if (!uint8ArrayEqual(storedPskId, options.psk.id)) continue;
      } else {
        // In base mode, psk_id MUST NOT be present
        if (rHeader.has(HeaderLabel.PSK_ID)) {
          continue;
        }
      }

      // Build HPKE info = Recipient_structure(contentAlg, protected, extraInfo)
      const hpkeInfo = buildRecipientStructure(
        this._contentAlg,
        rProtected,
        extraInfo,
      );

      try {
        // Build recipient context params
        const recipientParams: Parameters<
          CipherSuite["createRecipientContext"]
        >[0] = {
          recipientKey: privateKey,
          enc: rEnc,
          info: hpkeInfo,
        };
        if (options?.psk) {
          recipientParams.psk = {
            id: options.psk.id,
            key: options.psk.key,
          };
        }

        const ctx = await this._suite.createRecipientContext(recipientParams);
        cek = new Uint8Array(await ctx.open(rCiphertext, hpkeAad));
        break;
      } catch {
        continue;
      }
    }

    if (cek === null) {
      throw new CoseError("No matching recipient found or decryption failed");
    }

    // Decrypt content with CEK
    const contentAad = buildEncStructureEncrypt(protectedHeader, extAad);
    return await this._contentDecrypt(cek, nonce, ciphertext, contentAad);
  }

  private async _contentEncrypt(
    cek: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array> {
    return await this._contentCrypto.seal(cek, nonce, plaintext, aad);
  }

  private async _contentDecrypt(
    cek: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array> {
    return await this._contentCrypto.open(cek, nonce, ciphertext, aad);
  }

  private async _wrapCek(
    recipient: CoseRecipient,
    cek: Uint8Array,
  ): Promise<CborValue[]> {
    const extraInfo = recipient.extraInfo ?? EMPTY;
    const hpkeAad = recipient.aad ?? EMPTY;

    // Recipient protected header: { alg, [kid], [psk_id] }
    const rProtectedMap = new Map<CborValue, CborValue>();
    rProtectedMap.set(HeaderLabel.ALG, this._alg);
    if (recipient.kid) {
      rProtectedMap.set(HeaderLabel.KID, recipient.kid);
    }
    if (recipient.psk) {
      rProtectedMap.set(HeaderLabel.PSK_ID, recipient.psk.id);
    }
    const rProtectedHeader = encode(rProtectedMap);

    // HPKE info = Recipient_structure(contentAlg, protected, extraInfo)
    const hpkeInfo = buildRecipientStructure(
      this._contentAlg,
      rProtectedHeader,
      extraInfo,
    );

    // Build sender context params
    const senderParams: Parameters<CipherSuite["createSenderContext"]>[0] = {
      recipientPublicKey: recipient.recipientPublicKey,
      info: hpkeInfo,
    };
    if (recipient.psk) {
      senderParams.psk = {
        id: recipient.psk.id,
        key: recipient.psk.key,
      };
    }

    // Create sender context with the info
    const ctx = await this._suite.createSenderContext(senderParams);

    const encBytes = new Uint8Array(ctx.enc);
    const wrappedCek = new Uint8Array(await ctx.seal(cek, hpkeAad));

    // Recipient unprotected header: { ek: enc }
    const rUnprotectedMap = new Map<CborValue, CborValue>();
    rUnprotectedMap.set(HeaderLabel.EK, encBytes);

    // COSE_recipient = [protected, unprotected, ciphertext]
    return [rProtectedHeader, rUnprotectedMap, wrappedCek];
  }

  async importPublicCoseKey(coseKeyBytes: Uint8Array): Promise<CryptoKey> {
    const rawBytes = extractPublicKeyBytes(coseKeyBytes);
    return await this._suite.kem.importKey(
      "raw",
      rawBytes.buffer as ArrayBuffer,
      true,
    );
  }

  async importPrivateCoseKey(coseKeyBytes: Uint8Array): Promise<CryptoKey> {
    const rawBytes = extractPrivateKeyBytes(coseKeyBytes);
    return await this._suite.kem.importKey(
      "raw",
      rawBytes.buffer as ArrayBuffer,
      false,
    );
  }
}
