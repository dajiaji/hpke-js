import type { AeadInterface } from "@hpke/core";

import { JoseError } from "./errors.ts";

/**
 * JOSE HPKE algorithm identifiers from draft-ietf-jose-hpke-encrypt-22.
 *
 * Integrated Encryption: "HPKE-0" through "HPKE-7".
 * Key Encryption: "HPKE-0-KE" through "HPKE-7-KE", except "HPKE-4-KE" and
 * "HPKE-6-KE", which the draft does not define.
 */
export const JoseHpkeAlg = {
  /** DHKEM(P-256), HKDF-SHA256, AES-128-GCM */
  HPKE_0: "HPKE-0",
  /** DHKEM(P-384), HKDF-SHA384, AES-256-GCM */
  HPKE_1: "HPKE-1",
  /** DHKEM(P-521), HKDF-SHA512, AES-256-GCM */
  HPKE_2: "HPKE-2",
  /** DHKEM(X25519), HKDF-SHA256, AES-128-GCM */
  HPKE_3: "HPKE-3",
  /** DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305 */
  HPKE_4: "HPKE-4",
  /** DHKEM(X448), HKDF-SHA512, AES-256-GCM */
  HPKE_5: "HPKE-5",
  /** DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 */
  HPKE_6: "HPKE-6",
  /** DHKEM(P-256), HKDF-SHA256, AES-256-GCM */
  HPKE_7: "HPKE-7",
  /** Key Encryption: DHKEM(P-256), HKDF-SHA256, AES-128-GCM */
  HPKE_0_KE: "HPKE-0-KE",
  /** Key Encryption: DHKEM(P-384), HKDF-SHA384, AES-256-GCM */
  HPKE_1_KE: "HPKE-1-KE",
  /** Key Encryption: DHKEM(P-521), HKDF-SHA512, AES-256-GCM */
  HPKE_2_KE: "HPKE-2-KE",
  /** Key Encryption: DHKEM(X25519), HKDF-SHA256, AES-128-GCM */
  HPKE_3_KE: "HPKE-3-KE",
  /** Key Encryption: DHKEM(X448), HKDF-SHA512, AES-256-GCM */
  HPKE_5_KE: "HPKE-5-KE",
  /** Key Encryption: DHKEM(P-256), HKDF-SHA256, AES-256-GCM */
  HPKE_7_KE: "HPKE-7-KE",
} as const;

export type JoseHpkeAlg = (typeof JoseHpkeAlg)[keyof typeof JoseHpkeAlg];

/** JWE content-encryption algorithm identifiers. */
export const ContentEncAlg = {
  /** AES-128-GCM */
  A128GCM: "A128GCM",
  /** AES-256-GCM */
  A256GCM: "A256GCM",
} as const;

export type ContentEncAlg = (typeof ContentEncAlg)[keyof typeof ContentEncAlg];

/**
 * Map an HPKE AEAD object to its supported JWE content-encryption algorithm.
 *
 * @throws {JoseError} if the AEAD has no supported JWE equivalent.
 */
export function contentEncAlgFromAead(aead: AeadInterface): ContentEncAlg {
  let alg: ContentEncAlg;
  let keySize: number;
  switch (aead.id) {
    case 0x0001: // AeadId.Aes128Gcm
      alg = ContentEncAlg.A128GCM;
      keySize = 16;
      break;
    case 0x0002: // AeadId.Aes256Gcm
      alg = ContentEncAlg.A256GCM;
      keySize = 32;
      break;
    default:
      throw new JoseError(
        `Unsupported content encryption AEAD: id=0x${
          aead.id.toString(16).padStart(4, "0")
        }`,
      );
  }
  if (
    aead.keySize !== keySize || aead.nonceSize !== 12 || aead.tagSize !== 16
  ) {
    throw new JoseError(
      `Invalid content encryption AEAD parameters for ${alg}: expected keySize=${keySize}, nonceSize=12, tagSize=16`,
    );
  }
  return alg;
}

const KEY_ENCRYPTION_ALGS: ReadonlySet<string> = new Set([
  "HPKE-0-KE",
  "HPKE-1-KE",
  "HPKE-2-KE",
  "HPKE-3-KE",
  "HPKE-5-KE",
  "HPKE-7-KE",
]);
const INTEGRATED_ENCRYPTION_ALGS: ReadonlySet<string> = new Set([
  "HPKE-0",
  "HPKE-1",
  "HPKE-2",
  "HPKE-3",
  "HPKE-4",
  "HPKE-5",
  "HPKE-6",
  "HPKE-7",
]);

/** Whether the algorithm is for Key Encryption. */
export function isKeyEncryption(alg: JoseHpkeAlg): boolean {
  return KEY_ENCRYPTION_ALGS.has(alg);
}

/** Whether the algorithm is for Integrated Encryption. */
export function isIntegratedEncryption(alg: JoseHpkeAlg): boolean {
  return INTEGRATED_ENCRYPTION_ALGS.has(alg);
}
