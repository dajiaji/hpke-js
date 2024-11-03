/**
 * The supported HPKE modes.
 */
export const Mode = {
  Base: 0x00,
  Psk: 0x01,
  Auth: 0x02,
  AuthPsk: 0x03,
} as const;

/**
 * The type alias of the supported HPKE modes.
 */
export type Mode = typeof Mode[keyof typeof Mode];

/**
 * The supported Key Encapsulation Mechanism (KEM) identifiers.
 */
export const KemId = {
  NotAssigned: 0x0000,
  DhkemP256HkdfSha256: 0x0010,
  DhkemP384HkdfSha384: 0x0011,
  DhkemP521HkdfSha512: 0x0012,
  DhkemSecp256k1HkdfSha256: 0x0013,
  DhkemX25519HkdfSha256: 0x0020,
  DhkemX448HkdfSha512: 0x0021,
  HybridkemX25519Kyber768: 0x0030,
  HybridkemXWing: 0x647a,
} as const;

/**
 * The type alias of the supported KEM identifiers.
 */
export type KemId = typeof KemId[keyof typeof KemId];

/**
 * The supported Key Derivation Function (KDF) identifiers.
 */
export const KdfId = {
  HkdfSha256: 0x0001,
  HkdfSha384: 0x0002,
  HkdfSha512: 0x0003,
} as const;

/**
 * The type alias of the supported KDF identifiers.
 */
export type KdfId = typeof KdfId[keyof typeof KdfId];

/**
 * The supported Authenticated Encryption with Associated Data (AEAD) identifiers.
 */
export const AeadId = {
  Aes128Gcm: 0x0001,
  Aes256Gcm: 0x0002,
  Chacha20Poly1305: 0x0003,
  ExportOnly: 0xFFFF,
} as const;

/**
 * The type alias of the supported AEAD identifiers.
 */
export type AeadId = typeof AeadId[keyof typeof AeadId];
