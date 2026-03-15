import type { CipherSuite } from "@hpke/core";

import { encode, encodeTagged } from "./cbor/encoder.ts";
import { decode } from "./cbor/decoder.ts";
import type { CborValue } from "./cbor/types.ts";
import { type CoseHpkeAlg, isIntegratedEncryption } from "./alg.ts";
import { extractPrivateKeyBytes, extractPublicKeyBytes } from "./coseKey.ts";
import { CoseError } from "./errors.ts";
import { buildEncStructure, HeaderLabel } from "./structures.ts";

const EMPTY = new Uint8Array(0);

function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Options for CoseEncrypt0 seal/open operations. */
export interface CoseEncrypt0Options {
  /** External AAD included in the Enc_structure. */
  externalAad?: Uint8Array;
  /** HPKE info parameter. */
  info?: Uint8Array;
  /** Pre-shared key for PSK mode. */
  psk?: { id: Uint8Array; key: Uint8Array };
  /** Key identifier to include in the protected header (bstr per RFC 9052). */
  kid?: Uint8Array;
  /** If true, output is wrapped in CBOR Tag 16 (COSE_Encrypt0). */
  tagged?: boolean;
  /**
   * Detached ciphertext for open(). When provided, the ciphertext field
   * in the COSE structure (which should be null) is replaced by this value.
   */
  detachedPayload?: Uint8Array;
}

/** Result of a detached seal operation. */
export interface CoseEncrypt0DetachedResult {
  /** CBOR-encoded COSE_Encrypt0 with null ciphertext. */
  message: Uint8Array;
  /** The ciphertext transported separately. */
  payload: Uint8Array;
}

/**
 * COSE_Encrypt0 (Integrated Encryption) using HPKE.
 *
 * Implements draft-ietf-cose-hpke-24 Section 4 (Direct Key Agreement).
 */
export interface CoseEncrypt0 {
  /** The underlying HPKE CipherSuite. */
  readonly suite: CipherSuite;

  /**
   * Encrypt a plaintext into a CBOR-encoded COSE_Encrypt0 structure.
   */
  seal(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: CoseEncrypt0Options,
  ): Promise<Uint8Array>;

  /**
   * Encrypt a plaintext into a detached COSE_Encrypt0 structure.
   * The ciphertext field is null; the actual payload is returned separately.
   */
  sealDetached(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: CoseEncrypt0Options,
  ): Promise<CoseEncrypt0DetachedResult>;

  /**
   * Decrypt a CBOR-encoded COSE_Encrypt0 structure.
   * For detached payloads, pass the ciphertext via options.detachedPayload.
   */
  open(
    recipientKey: CryptoKeyPair | CryptoKey,
    data: Uint8Array,
    options?: CoseEncrypt0Options,
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
export class CoseEncrypt0Impl implements CoseEncrypt0 {
  private _alg: CoseHpkeAlg;
  private _suite: CipherSuite;

  /**
   * @param suite The HPKE CipherSuite to use.
   * @param alg A COSE HPKE algorithm identifier for Integrated Encryption (35-45).
   * @throws {CoseError} if alg is not an Integrated Encryption algorithm.
   */
  constructor(suite: CipherSuite, alg: CoseHpkeAlg) {
    if (!isIntegratedEncryption(alg)) {
      throw new CoseError(
        "CoseEncrypt0 requires an Integrated Encryption algorithm (35-45)",
      );
    }
    this._alg = alg;
    this._suite = suite;
  }

  /** The underlying HPKE CipherSuite. */
  get suite(): CipherSuite {
    return this._suite;
  }

  async seal(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: CoseEncrypt0Options,
  ): Promise<Uint8Array> {
    const { protectedHeader, unprotectedMap, ciphertext } = await this
      ._sealInner(recipientPublicKey, plaintext, options);
    const coseEncrypt0: CborValue[] = [
      protectedHeader,
      unprotectedMap,
      ciphertext,
    ];
    if (options?.tagged) {
      return encodeTagged(16, coseEncrypt0);
    }
    return encode(coseEncrypt0);
  }

  async sealDetached(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: CoseEncrypt0Options,
  ): Promise<CoseEncrypt0DetachedResult> {
    const { protectedHeader, unprotectedMap, ciphertext } = await this
      ._sealInner(recipientPublicKey, plaintext, options);
    const coseEncrypt0: CborValue[] = [
      protectedHeader,
      unprotectedMap,
      null,
    ];
    const message = options?.tagged
      ? encodeTagged(16, coseEncrypt0)
      : encode(coseEncrypt0);
    return { message, payload: ciphertext };
  }

  private async _sealInner(
    recipientPublicKey: CryptoKey,
    plaintext: Uint8Array,
    options?: CoseEncrypt0Options,
  ): Promise<{
    protectedHeader: Uint8Array;
    unprotectedMap: Map<CborValue, CborValue>;
    ciphertext: Uint8Array;
  }> {
    const externalAad = options?.externalAad ?? EMPTY;
    const info = options?.info ?? EMPTY;

    const senderParams: Parameters<CipherSuite["createSenderContext"]>[0] = {
      recipientPublicKey,
      info,
    };
    if (options?.psk) {
      senderParams.psk = {
        id: options.psk.id,
        key: options.psk.key,
      };
    }

    const ctx = await this._suite.createSenderContext(senderParams);
    const encBytes = new Uint8Array(ctx.enc);

    const protectedMap = new Map<CborValue, CborValue>();
    protectedMap.set(HeaderLabel.ALG, this._alg);
    if (options?.kid) {
      protectedMap.set(HeaderLabel.KID, options.kid);
    }
    if (options?.psk) {
      protectedMap.set(HeaderLabel.PSK_ID, options.psk.id);
    }
    const protectedHeader = encode(protectedMap);

    const unprotectedMap = new Map<CborValue, CborValue>();
    unprotectedMap.set(HeaderLabel.EK, encBytes);

    const aad = buildEncStructure(protectedHeader, externalAad);
    const ciphertext = new Uint8Array(await ctx.seal(plaintext, aad));

    return { protectedHeader, unprotectedMap, ciphertext };
  }

  /**
   * Decrypt a CBOR-encoded COSE_Encrypt0 structure.
   *
   * @param recipientKey The recipient's key pair or CryptoKey (private).
   * @param data CBOR-encoded COSE_Encrypt0.
   * @param options Optional external AAD, HPKE info, and PSK.
   * @returns Decrypted plaintext.
   */
  async open(
    recipientKey: CryptoKeyPair | CryptoKey,
    data: Uint8Array,
    options?: CoseEncrypt0Options,
  ): Promise<Uint8Array> {
    const externalAad = options?.externalAad ?? EMPTY;
    const info = options?.info ?? EMPTY;

    const decoded = decode(data);
    if (!Array.isArray(decoded) || decoded.length !== 3) {
      throw new CoseError("Invalid COSE_Encrypt0 structure");
    }

    const protectedHeader = decoded[0];
    const unprotectedHeader = decoded[1];
    const rawCiphertext = decoded[2];

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

    // Parse protected header to extract alg
    const headerMap = decode(protectedHeader);
    if (!(headerMap instanceof Map)) {
      throw new CoseError("Protected header is not a map");
    }

    // If alg is present, verify it matches. If absent, proceed with
    // the instance's configured algorithm (Postel's principle).
    const algValue = headerMap.get(HeaderLabel.ALG);
    if (algValue !== undefined && algValue !== this._alg) {
      throw new CoseError(
        `Algorithm mismatch: expected ${this._alg}, got ${algValue}`,
      );
    }

    // Read ek from unprotected header
    if (!(unprotectedHeader instanceof Map)) {
      throw new CoseError("Invalid unprotected header");
    }
    const encBytes = unprotectedHeader.get(HeaderLabel.EK);
    if (!(encBytes instanceof Uint8Array)) {
      throw new CoseError("Missing or invalid ek in unprotected header");
    }

    // Validate psk_id / mode consistency (draft-ietf-cose-hpke §4)
    // psk_id MUST be in the protected header per spec.
    if (options?.psk) {
      const storedPskId = headerMap.get(HeaderLabel.PSK_ID);
      if (!(storedPskId instanceof Uint8Array)) {
        throw new CoseError(
          "Missing psk_id in protected header for PSK mode",
        );
      }
      if (!uint8ArrayEqual(storedPskId, options.psk.id)) {
        throw new CoseError("psk_id mismatch");
      }
    } else {
      // In base mode, psk_id MUST NOT be present
      if (headerMap.has(HeaderLabel.PSK_ID)) {
        throw new CoseError(
          "psk_id present but PSK mode was not selected",
        );
      }
    }

    // Reconstruct AAD = Enc_structure("Encrypt0", protected, external_aad)
    const aad = buildEncStructure(protectedHeader, externalAad);

    const privateKey = "privateKey" in recipientKey
      ? (recipientKey as CryptoKeyPair).privateKey
      : recipientKey as CryptoKey;

    // Build recipient context params
    const recipientParams: Parameters<
      CipherSuite["createRecipientContext"]
    >[0] = {
      recipientKey: privateKey,
      enc: encBytes,
      info,
    };
    if (options?.psk) {
      recipientParams.psk = {
        id: options.psk.id,
        key: options.psk.key,
      };
    }

    const ctx = await this._suite.createRecipientContext(recipientParams);

    return new Uint8Array(await ctx.open(ciphertext, aad));
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
