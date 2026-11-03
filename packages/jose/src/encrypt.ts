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
import {
  type JweFlattenedJson,
  type JweGeneralJson,
  type JweJson,
  type JweRecipientJson,
  parseJwe,
} from "./serialization.ts";
import { buildRecipientStructure } from "./structures.ts";

const EMPTY = new Uint8Array(0);
const te = new TextEncoder();

/** A recipient descriptor for JoseEncrypt.seal(). */
export interface JoseRecipient {
  /** The recipient's public key. */
  recipientPublicKey: CryptoKey;
  /** Key identifier for the recipient. */
  kid?: string;
  /** Extra info embedded in Recipient_structure. */
  extraInfo?: Uint8Array;
  /**
   * Pre-shared key for PSK mode. `id` is the HPKE psk_id; it is carried in the
   * "psk_id" header parameter as BASE64URL(id).
   */
  psk?: { id: Uint8Array; key: Uint8Array };
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
  /** Pre-shared key for PSK mode. `id` is the HPKE psk_id. */
  psk?: { id: Uint8Array; key: Uint8Array };
  /** Key identifier to match against recipients. */
  kid?: string;
}

/**
 * JWE Key Encryption using HPKE.
 *
 * Implements draft-ietf-jose-hpke-encrypt-22 Section 6. seal() produces the
 * General JSON Serialization; open() accepts all JWE serializations.
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
   * Decrypt a JWE in the Compact, Flattened JSON or General JSON Serialization.
   * Header parameters are read from the union of the protected, shared
   * unprotected and per-recipient headers.
   */
  open(
    recipientKey: CryptoKeyPair | CryptoKey,
    jwe: string | JweFlattenedJson | JweGeneralJson,
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
    if (options?.aad && options.aad.length > 0) {
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
    jwe: string | JweFlattenedJson | JweGeneralJson,
    options?: JoseEncryptOpenOptions,
  ): Promise<Uint8Array> {
    const extraInfo = options?.extraInfo ?? EMPTY;

    const parsed = parseJwe(jwe);

    // Decode IV, ciphertext, tag
    if (!parsed.iv) {
      throw new JoseError("Missing IV");
    }
    if (!parsed.tag) {
      throw new JoseError("Missing authentication tag");
    }
    const nonce = decodeBase64Url(parsed.iv);
    const ct = decodeBase64Url(parsed.ciphertext);
    const tag = decodeBase64Url(parsed.tag);

    const privateKey = "privateKey" in recipientKey
      ? (recipientKey as CryptoKeyPair).privateKey
      : recipientKey as CryptoKey;

    // Find matching recipient and unwrap CEK
    let cek: Uint8Array | null = null;

    for (const { joseHeader, encryptedKey } of parsed.recipients) {
      // All recipients of a JWE share one content encryption algorithm
      if (joseHeader.enc !== this._contentEncAlg) {
        throw new JoseError(
          `Content encryption algorithm mismatch: expected ${this._contentEncAlg}, got ${joseHeader.enc}`,
        );
      }

      // Check algorithm matches
      if (joseHeader.alg !== this._alg) continue;

      // Match by kid if specified
      if (options?.kid && joseHeader.kid !== options.kid) continue;

      // Get ek (encapsulated key)
      const rEk = joseHeader.ek as string | undefined;
      if (!rEk || !encryptedKey) continue;

      // PSK consistency
      if (options?.psk) {
        if (joseHeader.psk_id !== encodeBase64Url(options.psk.id)) continue;
      } else {
        if ("psk_id" in joseHeader) continue;
      }

      const encBytes = decodeBase64Url(rEk);
      const wrappedCek = decodeBase64Url(encryptedKey);

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
          recipientParams.psk = options.psk;
        }

        const ctx = await this._suite.createRecipientContext(recipientParams);
        cek = new Uint8Array(await ctx.open(wrappedCek, EMPTY));
        break;
      } catch {
        continue;
      }
    }

    if (cek === null) {
      throw new JoseError("No matching recipient found or decryption failed");
    }

    // Combine ciphertext and tag for AES-GCM
    const combined = new Uint8Array(ct.length + tag.length);
    combined.set(ct);
    combined.set(tag, ct.length);

    return await this._contentCrypto.open(
      cek,
      nonce,
      combined,
      parsed.additionalData,
    );
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
      senderParams.psk = recipient.psk;
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
      rHeader.psk_id = encodeBase64Url(recipient.psk.id);
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
