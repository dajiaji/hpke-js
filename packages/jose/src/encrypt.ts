import type { CipherSuite } from "@hpke/core";

import {
  AES_GCM_TAG_SIZE,
  type ContentEncAlg,
  contentKeySize,
  contentNonceSize,
  isKeyEncryption,
  type JoseHpkeAlg,
} from "./alg.ts";
import { decodeBase64Url, encodeBase64Url } from "./utils.ts";
import type { ContentCrypto } from "./contentAesGcm.ts";
import { JoseError } from "./errors.ts";
import {
  extractPrivateKeyBytesFromJwk,
  extractPublicKeyBytesFromJwk,
} from "./jwk.ts";
import { buildRecipientStructure } from "./structures.ts";

const EMPTY = new Uint8Array(0);
const te = new TextEncoder();

/** A single JWE JSON recipient entry. */
export interface JweRecipientJson {
  header: Record<string, unknown>;
  encrypted_key: string;
}

/** JWE JSON Serialization structure. */
export interface JweJson {
  protected: string;
  unprotected?: Record<string, unknown>;
  iv: string;
  aad?: string;
  ciphertext: string;
  tag: string;
  recipients: JweRecipientJson[];
}

/** A recipient descriptor for JoseEncrypt.seal(). */
export interface JoseRecipient {
  /** The recipient's public key. */
  recipientPublicKey: CryptoKey;
  /** Key identifier for the recipient. */
  kid?: string;
  /** Extra info embedded in Recipient_structure. */
  extraInfo?: Uint8Array;
  /** Pre-shared key for PSK mode. */
  psk?: { id: string; key: Uint8Array };
}

/** Options for JoseEncrypt.seal(). */
export interface JoseEncryptSealOptions {
  /** Additional authenticated data (JWE AAD). */
  aad?: Uint8Array;
}

/** Options for JoseEncrypt.open(). */
export interface JoseEncryptOpenOptions {
  /** Extra info for Recipient_structure. */
  extraInfo?: Uint8Array;
  /** Pre-shared key for PSK mode. */
  psk?: { id: string; key: Uint8Array };
  /** Key identifier to match against recipients. */
  kid?: string;
}

/**
 * JWE Key Encryption using HPKE (JSON Serialization).
 *
 * Implements draft-ietf-jose-hpke-encrypt-16 Section 4
 * (Key Agreement with Key Wrap).
 */
export interface JoseEncrypt {
  /** The underlying HPKE CipherSuite. */
  readonly suite: CipherSuite;

  /** Generate a KEM key pair. */
  generateKemKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Encrypt plaintext into a JWE JSON Serialization structure.
   */
  seal(
    recipients: JoseRecipient[],
    plaintext: Uint8Array,
    options?: JoseEncryptSealOptions,
  ): Promise<JweJson>;

  /**
   * Decrypt a JWE JSON Serialization structure.
   */
  open(
    recipientKey: CryptoKeyPair | CryptoKey,
    jwe: JweJson,
    options?: JoseEncryptOpenOptions,
  ): Promise<Uint8Array>;

  /**
   * Import a public key from a JWK.
   */
  importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey>;

  /**
   * Import a private key from a JWK.
   */
  importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey>;
}

/** @internal */
export class JoseEncryptImpl implements JoseEncrypt {
  private _suite: CipherSuite;
  private _alg: JoseHpkeAlg;
  private _contentEncAlg: ContentEncAlg;
  private _contentCrypto: ContentCrypto;

  constructor(
    suite: CipherSuite,
    alg: JoseHpkeAlg,
    contentEncAlg: ContentEncAlg,
    contentCrypto: ContentCrypto,
  ) {
    if (!isKeyEncryption(alg)) {
      throw new JoseError(
        `JoseEncrypt requires a Key Encryption algorithm, got ${alg}`,
      );
    }
    this._suite = suite;
    this._alg = alg;
    this._contentEncAlg = contentEncAlg;
    this._contentCrypto = contentCrypto;
  }

  get suite(): CipherSuite {
    return this._suite;
  }

  async generateKemKeyPair(): Promise<CryptoKeyPair> {
    return await this._suite.kem.generateKeyPair();
  }

  async seal(
    recipients: JoseRecipient[],
    plaintext: Uint8Array,
    options?: JoseEncryptSealOptions,
  ): Promise<JweJson> {
    if (recipients.length === 0) {
      throw new JoseError("At least one recipient is required");
    }

    const keySize = contentKeySize(this._contentEncAlg);
    const nonceSize = contentNonceSize(this._contentEncAlg);

    const cek = crypto.getRandomValues(new Uint8Array(keySize));
    const nonce = crypto.getRandomValues(new Uint8Array(nonceSize));

    // Build protected header: { "enc": "A128GCM" }
    const protectedHeaderObj: Record<string, unknown> = {
      enc: this._contentEncAlg,
    };
    const encodedProtectedHeader = encodeBase64Url(
      te.encode(JSON.stringify(protectedHeaderObj)),
    );

    // Content AAD = ASCII(EPH) or ASCII(EPH || '.' || BASE64URL(JWE AAD))
    let contentAad: string;
    let jweAad: string | undefined;
    if (options?.aad) {
      jweAad = encodeBase64Url(options.aad);
      contentAad = `${encodedProtectedHeader}.${jweAad}`;
    } else {
      contentAad = encodedProtectedHeader;
    }
    const aadBytes = te.encode(contentAad);

    // Encrypt content with CEK
    const combined = await this._contentCrypto.seal(
      cek,
      nonce,
      plaintext,
      aadBytes,
    );

    // Split ciphertext and tag
    const ct = combined.slice(0, combined.length - AES_GCM_TAG_SIZE);
    const tag = combined.slice(combined.length - AES_GCM_TAG_SIZE);

    // Wrap CEK for each recipient
    const recipientEntries: JweRecipientJson[] = [];
    for (const r of recipients) {
      const entry = await this._wrapCek(r, cek);
      recipientEntries.push(entry);
    }

    const result: JweJson = {
      protected: encodedProtectedHeader,
      iv: encodeBase64Url(nonce),
      ciphertext: encodeBase64Url(ct),
      tag: encodeBase64Url(tag),
      recipients: recipientEntries,
    };
    if (jweAad) {
      result.aad = jweAad;
    }
    return result;
  }

  async open(
    recipientKey: CryptoKeyPair | CryptoKey,
    jwe: JweJson,
    options?: JoseEncryptOpenOptions,
  ): Promise<Uint8Array> {
    const extraInfo = options?.extraInfo ?? EMPTY;

    const encodedProtectedHeader = jwe.protected;
    if (!encodedProtectedHeader) {
      throw new JoseError("Missing protected header");
    }

    // Parse protected header
    let headerObj: Record<string, unknown>;
    try {
      headerObj = JSON.parse(
        new TextDecoder().decode(decodeBase64Url(encodedProtectedHeader)),
      );
    } catch {
      throw new JoseError("Invalid protected header");
    }

    // Validate enc
    const encValue = headerObj.enc as string | undefined;
    if (encValue !== undefined && encValue !== this._contentEncAlg) {
      throw new JoseError(
        `Content encryption algorithm mismatch: expected ${this._contentEncAlg}, got ${encValue}`,
      );
    }

    // Decode IV, ciphertext, tag
    if (!jwe.iv) {
      throw new JoseError("Missing IV");
    }
    const nonce = decodeBase64Url(jwe.iv);
    const ct = decodeBase64Url(jwe.ciphertext);
    const tag = decodeBase64Url(jwe.tag);

    if (!jwe.recipients || !Array.isArray(jwe.recipients)) {
      throw new JoseError("Missing or invalid recipients array");
    }

    const privateKey = "privateKey" in recipientKey
      ? (recipientKey as CryptoKeyPair).privateKey
      : recipientKey as CryptoKey;

    // Find matching recipient and unwrap CEK
    let cek: Uint8Array | null = null;

    for (const entry of jwe.recipients) {
      const rHeader = entry.header;
      if (!rHeader) continue;

      // Check algorithm matches
      const rAlg = rHeader.alg as string | undefined;
      if (rAlg !== undefined && rAlg !== this._alg) continue;

      // Match by kid if specified
      if (options?.kid) {
        const rKid = rHeader.kid as string | undefined;
        if (rKid !== options.kid) continue;
      }

      // Get ek (encapsulated key)
      const rEk = rHeader.ek as string | undefined;
      if (!rEk) continue;

      // PSK consistency
      if (options?.psk) {
        const rPskId = rHeader.psk_id as string | undefined;
        if (rPskId !== options.psk.id) continue;
      } else {
        if ("psk_id" in rHeader) continue;
      }

      const encBytes = decodeBase64Url(rEk);
      const encryptedKey = decodeBase64Url(entry.encrypted_key);

      // Build HPKE info = Recipient_structure(enc_alg, extra_info)
      const hpkeInfo = buildRecipientStructure(
        this._contentEncAlg,
        extraInfo,
      );

      try {
        const recipientParams: Parameters<
          CipherSuite["createRecipientContext"]
        >[0] = {
          recipientKey: privateKey,
          enc: encBytes,
          info: hpkeInfo,
        };
        if (options?.psk) {
          recipientParams.psk = {
            id: te.encode(options.psk.id),
            key: options.psk.key,
          };
        }

        const ctx = await this._suite.createRecipientContext(recipientParams);
        cek = new Uint8Array(await ctx.open(encryptedKey, EMPTY));
        break;
      } catch {
        continue;
      }
    }

    if (cek === null) {
      throw new JoseError("No matching recipient found or decryption failed");
    }

    // Reconstruct content AAD
    let contentAad: string;
    if (jwe.aad) {
      contentAad = `${encodedProtectedHeader}.${jwe.aad}`;
    } else {
      contentAad = encodedProtectedHeader;
    }
    const aadBytes = te.encode(contentAad);

    // Combine ciphertext and tag for AES-GCM
    const combined = new Uint8Array(ct.length + tag.length);
    combined.set(ct);
    combined.set(tag, ct.length);

    return await this._contentCrypto.open(cek, nonce, combined, aadBytes);
  }

  private async _wrapCek(
    recipient: JoseRecipient,
    cek: Uint8Array,
  ): Promise<JweRecipientJson> {
    const extraInfo = recipient.extraInfo ?? EMPTY;

    // Build HPKE info = Recipient_structure(enc_alg, extra_info)
    const hpkeInfo = buildRecipientStructure(
      this._contentEncAlg,
      extraInfo,
    );

    const senderParams: Parameters<CipherSuite["createSenderContext"]>[0] = {
      recipientPublicKey: recipient.recipientPublicKey,
      info: hpkeInfo,
    };
    if (recipient.psk) {
      senderParams.psk = {
        id: te.encode(recipient.psk.id),
        key: recipient.psk.key,
      };
    }

    const ctx = await this._suite.createSenderContext(senderParams);
    const encBytes = new Uint8Array(ctx.enc);
    const wrappedCek = new Uint8Array(await ctx.seal(cek, EMPTY));

    // Per-recipient unprotected header
    const rHeader: Record<string, unknown> = {
      alg: this._alg,
      ek: encodeBase64Url(encBytes),
    };
    if (recipient.kid) {
      rHeader.kid = recipient.kid;
    }
    if (recipient.psk) {
      rHeader.psk_id = recipient.psk.id;
    }

    return {
      header: rHeader,
      encrypted_key: encodeBase64Url(wrappedCek),
    };
  }

  async importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
    const rawBytes = extractPublicKeyBytesFromJwk(jwk, this._alg);
    return await this._suite.kem.importKey(
      "raw",
      rawBytes.buffer as ArrayBuffer,
      true,
    );
  }

  async importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
    const rawBytes = extractPrivateKeyBytesFromJwk(jwk, this._alg);
    return await this._suite.kem.importKey(
      "raw",
      rawBytes.buffer as ArrayBuffer,
      false,
    );
  }
}
