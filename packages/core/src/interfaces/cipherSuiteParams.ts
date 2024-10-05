import type { AeadId, KdfId, KemId } from "@hpke/common";
import type { AeadInterface } from "@hpke/common";
import type { KdfInterface } from "./kdfInterface.ts";
import type { KemInterface } from "./kemInterface.ts";

/**
 * The parameters used to configure the `CipherSuite`.
 */
export interface CipherSuiteParams {
  /** The KEM (Key Encapsulation Mechanism) identifier or the KEM object. */
  kem: KemId | KemInterface;

  /** The KDF (Key Derivation Function) identifier or the KDF object. */
  kdf: KdfId | KdfInterface;

  /** The AEAD (Authenticated Encryption with Addtional Data) identifier or the AEAD object. */
  aead: AeadId | AeadInterface;
}
