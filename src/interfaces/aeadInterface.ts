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
   */
  init(api: SubtleCrypto): void;

  /**
   * Creates an AeadKey which has seal/open operation.
   */
  createAeadKey(key: ArrayBuffer): AeadKey;
}
