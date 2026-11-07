import type { CipherSuite } from "@hpke/core";

import { isIntegratedEncryption, type JoseHpkeAlg } from "./alg.ts";
import { decodeBase64Url, encodeBase64Url } from "./utils.ts";
import { JoseError } from "./errors.ts";
import {
  type JweFlattenedJson,
  type JweGeneralJson,
  parseJwe,
} from "./serialization.ts";
import {
  extractPrivateKeyBytesFromJwk,
  extractPublicKeyBytesFromJwk,
} from "./jwk.ts";

const EMPTY = new Uint8Array(0);
const te = new TextEncoder();

/** Options for JoseEncrypt0 seal/open operations. */
export interface JoseEncrypt0Options {
  /** HPKE info parameter. Defaults to empty. */
  info?: Uint8Array;
  /**
   * Pre-shared key for PSK mode. `id` is the HPKE psk_id; it is carried in the
   * "psk_id" header parameter as BASE64URL(id).
   */
  psk?: { id: Uint8Array; key: Uint8Array };
  /** Key identifier to include in the protected header. */
  kid?: string;
}

/**
 * JWE Integrated Encryption using HPKE.
 *
 * Implements draft-ietf-jose-hpke-encrypt-22 Section 5. seal() produces the
 * Compact Serialization; open() accepts all JWE serializations.
 */
export interface JoseEncrypt0 {
  /** The underlying HPKE CipherSuite. */
  readonly suite: CipherSuite;

  /** Generate a KEM key pair. */
  generateKemKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Encrypt a plaintext into a JWE Compact Serialization string.
   *
   * Format: BASE64URL(header).BASE64URL(enc)..BASE64URL(ct).
   */
  seal(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: JoseEncrypt0Options,
  ): Promise<string>;

  /**
   * Decrypt a JWE in the Compact, Flattened JSON or General JSON Serialization.
   * The JWE AAD, if any, is taken from the "aad" member.
   */
  open(
    recipientKey: CryptoKeyPair | CryptoKey,
    jwe: string | JweFlattenedJson | JweGeneralJson,
    options?: JoseEncrypt0Options,
  ): Promise<Uint8Array>;

  /**
   * Import a public key from a JWK.
   * Validates kty and crv against the algorithm.
   */
  importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey>;

  /**
   * Import a private key from a JWK.
   * Validates kty and crv against the algorithm.
   */
  importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey>;
}

/** @internal */
export class JoseEncrypt0Impl implements JoseEncrypt0 {
  private _alg: JoseHpkeAlg;
  private _suite: CipherSuite;

  constructor(suite: CipherSuite, alg: JoseHpkeAlg) {
    if (!isIntegratedEncryption(alg)) {
      throw new JoseError(
        "JoseEncrypt0 requires an Integrated Encryption algorithm",
      );
    }
    this._alg = alg;
    this._suite = suite;
  }

  get suite(): CipherSuite {
    return this._suite;
  }

  async generateKemKeyPair(): Promise<CryptoKeyPair> {
    return await this._suite.kem.generateKeyPair();
  }

  async seal(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: JoseEncrypt0Options,
  ): Promise<string> {
    const info = options?.info ?? EMPTY;

    const senderParams: Parameters<CipherSuite["createSenderContext"]>[0] = {
      recipientPublicKey,
      info,
    };
    if (options?.psk) {
      senderParams.psk = options.psk;
    }

    const ctx = await this._suite.createSenderContext(senderParams);
    const encBytes = new Uint8Array(ctx.enc);

    // Build protected header
    const header: Record<string, unknown> = { alg: this._alg };
    if (options?.kid) {
      header.kid = options.kid;
    }
    if (options?.psk) {
      header.psk_id = encodeBase64Url(options.psk.id);
    }
    const encodedProtectedHeader = encodeBase64Url(
      te.encode(JSON.stringify(header)),
    );

    // AAD = ASCII(Encoded Protected Header)
    const aad = te.encode(encodedProtectedHeader);
    const ciphertext = new Uint8Array(await ctx.seal(plaintext, aad));

    // Compact JWE: header.enc..ct.
    // IV and tag are empty for Integrated Encryption
    return `${encodedProtectedHeader}.${encodeBase64Url(encBytes)}..${
      encodeBase64Url(ciphertext)
    }.`;
  }

  async open(
    recipientKey: CryptoKeyPair | CryptoKey,
    jwe: string | JweFlattenedJson | JweGeneralJson,
    options?: JoseEncrypt0Options,
  ): Promise<Uint8Array> {
    const info = options?.info ?? EMPTY;

    const parsed = parseJwe(jwe);
    if (parsed.recipients.length !== 1) {
      throw new JoseError(
        "Integrated Encryption requires exactly one recipient",
      );
    }
    const { joseHeader: header, encryptedKey } = parsed.recipients[0];

    // "alg" MUST be in the protected header for Integrated Encryption
    const algValue = parsed.protectedHeader.alg;
    if (algValue !== this._alg) {
      throw new JoseError(
        `Algorithm mismatch: expected ${this._alg}, got ${algValue}`,
      );
    }

    // "enc" MUST NOT be present for Integrated Encryption
    if ("enc" in header) {
      throw new JoseError(
        "enc parameter must not be present for Integrated Encryption",
      );
    }

    // "ek" MUST NOT be present for Integrated Encryption
    if ("ek" in header) {
      throw new JoseError(
        "ek parameter must not be present for Integrated Encryption",
      );
    }

    // The JWE IV and Authentication Tag MUST be empty
    if (parsed.iv || parsed.tag) {
      throw new JoseError(
        "iv and tag must be empty for Integrated Encryption",
      );
    }

    if (!encryptedKey || !parsed.ciphertext) {
      throw new JoseError("Missing encrypted key or ciphertext");
    }

    // PSK consistency validation
    if (options?.psk) {
      const storedPskId = parsed.protectedHeader.psk_id;
      if (storedPskId === undefined) {
        throw new JoseError(
          "Missing psk_id in protected header for PSK mode",
        );
      }
      if (storedPskId !== encodeBase64Url(options.psk.id)) {
        throw new JoseError("psk_id mismatch");
      }
    } else {
      if ("psk_id" in header) {
        throw new JoseError(
          "psk_id present but PSK mode was not selected",
        );
      }
    }

    const encBytes = decodeBase64Url(encryptedKey);
    const ciphertext = decodeBase64Url(parsed.ciphertext);

    const privateKey = "privateKey" in recipientKey
      ? (recipientKey as CryptoKeyPair).privateKey
      : recipientKey as CryptoKey;

    const recipientParams: Parameters<
      CipherSuite["createRecipientContext"]
    >[0] = {
      recipientKey: privateKey,
      enc: encBytes,
      info,
    };
    if (options?.psk) {
      recipientParams.psk = options.psk;
    }

    const ctx = await this._suite.createRecipientContext(recipientParams);
    return new Uint8Array(await ctx.open(ciphertext, parsed.additionalData));
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
