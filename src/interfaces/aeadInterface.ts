import type { AeadKey } from "./aeadKey.ts";

import { AeadId } from "../identifiers.ts";

/**
 * The AEAD interface.
 */
export interface AeadInterface {
  /** The KDF identifier. */
  readonly id: AeadId;
  /** The length in bytes of an AEAD key (Nk). */
  readonly keySize: number;
  /** The length in bytes of an AEAD nonce (Nn). */
  readonly nonceSize: number;
  /** The length in bytes of an AEAD authentication tag (Nt). */
  readonly tagSize: number;

  /**
   * Initializes the key by setting the SubtleCrypto.
   *
   * @param api A SubtleCrypto API.
   */
  init(api: SubtleCrypto): void;

  /**
   * Creates an AEAD encryption context which has seal/open operation.
   *
   * @param key A byte string of the raw key.
   *
   * @returns An AEAD encryption context.
   */
  createAeadKey(key: ArrayBuffer): AeadKey;
}
