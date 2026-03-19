import type { CipherSuite } from "@hpke/core";

import { isIntegratedEncryption, type JoseHpkeAlg } from "./alg.ts";
import { decodeBase64Url, encodeBase64Url } from "./utils.ts";
import { JoseError } from "./errors.ts";
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
  /** Pre-shared key for PSK mode. */
  psk?: { id: string; key: Uint8Array };
  /** Key identifier to include in the protected header. */
  kid?: string;
}

/**
 * JWE Integrated Encryption using HPKE (Compact Serialization).
 *
 * Implements draft-ietf-jose-hpke-encrypt-16 Section 3
 * (Direct Key Agreement).
 */
export interface JoseEncrypt0 {
  /** The underlying HPKE CipherSuite. */
  readonly suite: CipherSuite;

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
   * Decrypt a JWE Compact Serialization string.
   */
  open(
    recipientKey: CryptoKeyPair | CryptoKey,
    jwe: string,
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
      senderParams.psk = {
        id: te.encode(options.psk.id),
        key: options.psk.key,
      };
    }

    const ctx = await this._suite.createSenderContext(senderParams);
    const encBytes = new Uint8Array(ctx.enc);

    // Build protected header
    const header: Record<string, unknown> = { alg: this._alg };
    if (options?.kid) {
      header.kid = options.kid;
    }
    if (options?.psk) {
      header.psk_id = options.psk.id;
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
    jwe: string,
    options?: JoseEncrypt0Options,
  ): Promise<Uint8Array> {
    const info = options?.info ?? EMPTY;

    // Parse compact JWE: header.encryptedKey.iv.ciphertext.tag
    const parts = jwe.split(".");
    if (parts.length !== 5) {
      throw new JoseError("Invalid JWE Compact Serialization");
    }

    const [encodedProtectedHeader, encodedEncryptedKey, , encodedCiphertext] =
      parts;

    if (!encodedProtectedHeader || !encodedEncryptedKey || !encodedCiphertext) {
      throw new JoseError("Invalid JWE Compact Serialization");
    }

    // Decode and validate protected header
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(
        new TextDecoder().decode(decodeBase64Url(encodedProtectedHeader)),
      );
    } catch {
      throw new JoseError("Invalid protected header");
    }

    // Validate algorithm
    const algValue = header.alg as string | undefined;
    if (algValue !== undefined && algValue !== this._alg) {
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

    // PSK consistency validation
    if (options?.psk) {
      const storedPskId = header.psk_id as string | undefined;
      if (storedPskId === undefined) {
        throw new JoseError(
          "Missing psk_id in protected header for PSK mode",
        );
      }
      if (storedPskId !== options.psk.id) {
        throw new JoseError("psk_id mismatch");
      }
    } else {
      if ("psk_id" in header) {
        throw new JoseError(
          "psk_id present but PSK mode was not selected",
        );
      }
    }

    const encBytes = decodeBase64Url(encodedEncryptedKey);
    const ciphertext = decodeBase64Url(encodedCiphertext);

    // AAD = ASCII(Encoded Protected Header)
    const aad = te.encode(encodedProtectedHeader);

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
      recipientParams.psk = {
        id: te.encode(options.psk.id),
        key: options.psk.key,
      };
    }

    const ctx = await this._suite.createRecipientContext(recipientParams);
    return new Uint8Array(await ctx.open(ciphertext, aad));
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
