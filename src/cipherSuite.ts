import type { CipherSuiteParams } from "./interfaces/cipherSuiteParams.ts";

import { Aes128Gcm, Aes256Gcm } from "./aeads/aesGcm.ts";
import { ExportOnly } from "./aeads/exportOnly.ts";
import { Chacha20Poly1305 } from "./aeads/chacha20Poly1305.ts";
import { HkdfSha256 } from "./kdfs/hkdfSha256.ts";
import { HkdfSha384 } from "./kdfs/hkdfSha384.ts";
import { HkdfSha512 } from "./kdfs/hkdfSha512.ts";
import { DhkemP256HkdfSha256 } from "./kems/dhkemP256.ts";
import { DhkemP384HkdfSha384 } from "./kems/dhkemP384.ts";
import { DhkemP521HkdfSha512 } from "./kems/dhkemP521.ts";
import { DhkemX25519HkdfSha256 } from "./kems/dhkemX25519.ts";
import { DhkemX448HkdfSha512 } from "./kems/dhkemX448.ts";
import { AeadId, KdfId, KemId } from "./identifiers.ts";
import { CipherSuiteNative } from "./cipherSuiteNative.ts";

import * as errors from "./errors.ts";

/**
 * The class of Hybrid Public Key Encryption (HPKE) cipher suite.
 * The calling of the constructor of this class is the starting
 * point for HPKE operations for both senders and recipients.
 *
 * This class provides following functions:
 *
 * - Generates a key pair for the cipher suite.
 * - Derives a key pair for the cipher suite.
 * - Imports and converts a key to a CryptoKey.
 * - Creates an encryption context both for senders and recipients.
 * - Encrypts a message as a single-shot API.
 * - Decrypts an encrypted message as as single-shot API.
 */
export class CipherSuite extends CipherSuiteNative {
  /**
   * @param params A set of parameters for building a cipher suite.
   *
   * If the error occurred, throws `InvalidParamError`.
   *
   * @throws {@link InvalidParamError}
   */
  constructor(params: CipherSuiteParams) {
    // KEM
    if (typeof params.kem === "number") {
      switch (params.kem) {
        case KemId.DhkemP256HkdfSha256:
          params.kem = new DhkemP256HkdfSha256();
          break;
        case KemId.DhkemP384HkdfSha384:
          params.kem = new DhkemP384HkdfSha384();
          break;
        case KemId.DhkemP521HkdfSha512:
          params.kem = new DhkemP521HkdfSha512();
          break;
        case KemId.DhkemX25519HkdfSha256:
          params.kem = new DhkemX25519HkdfSha256();
          break;
        case KemId.DhkemX448HkdfSha512:
          params.kem = new DhkemX448HkdfSha512();
          break;
        default:
          throw new errors.InvalidParamError(
            `The KEM (${params.kem}) cannot be specified by KemId. Use submodule for the KEM`,
          );
      }
    }

    // KDF
    if (typeof params.kdf === "number") {
      switch (params.kdf) {
        case KdfId.HkdfSha256:
          params.kdf = new HkdfSha256();
          break;
        case KdfId.HkdfSha384:
          params.kdf = new HkdfSha384();
          break;
        default:
          // case KdfId.HkdfSha512:
          params.kdf = new HkdfSha512();
          break;
      }
    }

    // AEAD
    if (typeof params.aead === "number") {
      switch (params.aead) {
        case AeadId.Aes128Gcm:
          params.aead = new Aes128Gcm();
          break;
        case AeadId.Aes256Gcm:
          params.aead = new Aes256Gcm();
          break;
        case AeadId.Chacha20Poly1305:
          params.aead = new Chacha20Poly1305();
          break;
        default:
          // case AeadId.ExportOnly:
          params.aead = new ExportOnly();
          break;
      }
    }
    super(params);
  }
}
