/**
 * The supported Key Encapsulation Mechanism (KEM) identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export const Kem = {
  NotAssigned: 0x0000,
  DhkemP256HkdfSha256: 0x0010,
  DhkemP384HkdfSha384: 0x0011,
  DhkemP521HkdfSha512: 0x0012,
  DhkemSecp256k1HkdfSha256: 0x0013,
  DhkemX25519HkdfSha256: 0x0020,
  DhkemX448HkdfSha512: 0x0021,
  HybridkemX25519Kyber768: 0x0030,
} as const;

/**
 * The type alias of the supported KEM identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export type Kem = typeof Kem[keyof typeof Kem];

/**
 * The supported Key Derivation Function (KDF) identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export const Kdf = {
  HkdfSha256: 0x0001,
  HkdfSha384: 0x0002,
  HkdfSha512: 0x0003,
} as const;

/**
 * The type alias of the supported KDF identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export type Kdf = typeof Kdf[keyof typeof Kdf];

/**
 * The supported Authenticated Encryption with Associated Data (AEAD) identifiers.
 *
 * @deprecated Use {@link AeadId} instead.
 */
export const Aead = {
  Aes128Gcm: 0x0001,
  Aes256Gcm: 0x0002,
  Chacha20Poly1305: 0x0003,
  ExportOnly: 0xFFFF,
} as const;

/**
 * The type alias of the supported AEAD identifiers.
 *
 * @deprecated Use {@link AeadId} instead.
 */
export type Aead = typeof Aead[keyof typeof Aead];
