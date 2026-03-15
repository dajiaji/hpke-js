import { CoseError } from "./errors.ts";

/**
 * COSE HPKE algorithm identifiers from draft-ietf-cose-hpke-24.
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

/** Content key sizes in bytes for each ContentAlg. */
export function contentKeySize(alg: ContentAlg): number {
  switch (alg) {
    case ContentAlg.A128GCM:
      return 16;
    case ContentAlg.A256GCM:
      return 32;
    case ContentAlg.CHACHA20POLY1305:
      return 32;
    default:
      throw new CoseError(`Unsupported content algorithm: ${alg}`);
  }
}

/** Content nonce sizes in bytes for each ContentAlg. */
export function contentNonceSize(_alg: ContentAlg): number {
  // AES-128-GCM, AES-256-GCM, and ChaCha20/Poly1305 all use 12-byte nonces
  return 12;
}

const KEY_ENCRYPTION_ALGS: ReadonlySet<number> = new Set([
  46,
  47,
  48,
  49,
  50,
  51,
  52,
  53,
]);
const INTEGRATED_ENCRYPTION_ALGS: ReadonlySet<number> = new Set([
  35,
  37,
  39,
  41,
  42,
  43,
  44,
  45,
]);

/** Whether the algorithm is for Key Encryption (COSE_Encrypt). */
export function isKeyEncryption(alg: CoseHpkeAlg): boolean {
  return KEY_ENCRYPTION_ALGS.has(alg);
}

/** Whether the algorithm is for Integrated Encryption (COSE_Encrypt0). */
export function isIntegratedEncryption(alg: CoseHpkeAlg): boolean {
  return INTEGRATED_ENCRYPTION_ALGS.has(alg);
}
