import type { AeadId, KdfId, KemId } from "../identifiers.ts";
import type { KdfInterface } from "./kdfInterface.ts";
import type { KemInterface } from "./kemInterface.ts";

/**
 * The parameters used to configure the `CipherSuite`.
 */
export interface CipherSuiteParams {
  /** The KEM (Key Encapsulation Mechanism) identifier or the KEM object. */
  kem: KemId | KemInterface;

  /** The KDF (Key Derivation Function) identifier. */
  kdf: KdfId | KdfInterface;

  /** The AEAD (Authenticated Encryption with Addtional Data) identifier. */
  aead: AeadId;
}
