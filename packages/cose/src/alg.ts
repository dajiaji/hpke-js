import type { AeadInterface } from "@hpke/core";

import { CoseError } from "./errors.ts";

/**
 * COSE HPKE algorithm identifiers from draft-ietf-cose-hpke-27.
 *
 * Integrated Encryption (COSE_Encrypt0): values 35–45.
 * Key Encryption (COSE_Encrypt): values 46–53.
 */
export const CoseHpkeAlg = {
  /** DHKEM(P-256), HKDF-SHA256, AES-128-GCM */
  HPKE_0: 35,
  /** DHKEM(P-384), HKDF-SHA384, AES-256-GCM */
  HPKE_1: 37,
  /** DHKEM(P-521), HKDF-SHA512, AES-256-GCM */
  HPKE_2: 39,
  /** DHKEM(X25519), HKDF-SHA256, AES-128-GCM */
  HPKE_3: 41,
  /** DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305 */
  HPKE_4: 42,
  /** DHKEM(X448), HKDF-SHA512, AES-256-GCM */
  HPKE_5: 43,
  /** DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 */
  HPKE_6: 44,
  /** DHKEM(P-256), HKDF-SHA256, AES-256-GCM */
  HPKE_7: 45,
  /** Key Encryption: DHKEM(P-256), HKDF-SHA256, AES-128-GCM */
  HPKE_0_KE: 46,
  /** Key Encryption: DHKEM(P-384), HKDF-SHA384, AES-256-GCM */
  HPKE_1_KE: 47,
  /** Key Encryption: DHKEM(P-521), HKDF-SHA512, AES-256-GCM */
  HPKE_2_KE: 48,
  /** Key Encryption: DHKEM(X25519), HKDF-SHA256, AES-128-GCM */
  HPKE_3_KE: 49,
  /** Key Encryption: DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305 */
  HPKE_4_KE: 50,
  /** Key Encryption: DHKEM(X448), HKDF-SHA512, AES-256-GCM */
  HPKE_5_KE: 51,
  /** Key Encryption: DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 */
  HPKE_6_KE: 52,
  /** Key Encryption: DHKEM(P-256), HKDF-SHA256, AES-256-GCM */
  HPKE_7_KE: 53,
} as const;

export type CoseHpkeAlg = (typeof CoseHpkeAlg)[keyof typeof CoseHpkeAlg];

/** COSE content-encryption algorithm identifiers. */
export const ContentAlg = {
  /** AES-128-GCM (COSE alg value 1) */
  A128GCM: 1,
  /** AES-256-GCM (COSE alg value 3) */
  A256GCM: 3,
  /** ChaCha20/Poly1305 (COSE alg value 24) */
  CHACHA20POLY1305: 24,
} as const;

export type ContentAlg = (typeof ContentAlg)[keyof typeof ContentAlg];

/**
 * Map an HPKE AEAD object (e.g. `new Aes128Gcm()`) to the COSE content
 * encryption algorithm it implements.
 *
 * @throws {CoseError} if the AEAD has no COSE content-encryption equivalent
 *   (e.g. Export-Only).
 */
export function contentAlgFromAead(aead: AeadInterface): ContentAlg {
  switch (aead.id) {
    case 0x0001: // AeadId.Aes128Gcm
      return ContentAlg.A128GCM;
    case 0x0002: // AeadId.Aes256Gcm
      return ContentAlg.A256GCM;
    case 0x0003: // AeadId.Chacha20Poly1305
      return ContentAlg.CHACHA20POLY1305;
    default:
      throw new CoseError(
        `Unsupported content encryption AEAD: id=0x${
          aead.id.toString(16).padStart(4, "0")
        }`,
      );
  }
}
