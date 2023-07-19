import type { AeadId, KdfId, KemId } from "../identifiers.ts";

/**
 * The parameters used to configure the `CipherSuite`.
 */
export interface CipherSuiteParams {
  /** The type of KEM (Key Encapsulation Mechanism). */
  kem: KemId;

  /** The type of KDF (Key Derivation Function). */
  kdf: KdfId;

  /** The type of AEAD (Authenticated Encryption with Addtional Data) encryption function. */
  aead: AeadId;
}
