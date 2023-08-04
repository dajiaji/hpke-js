/**
 * Supported HPKE modes.
 */
export const Mode = {
  Base: 0x00,
  Psk: 0x01,
  Auth: 0x02,
  AuthPsk: 0x03,
} as const;

export type Mode = typeof Mode[keyof typeof Mode];

/**
 * Supported Key Encapsulation Mechanisms (KEMs).
 *
 * DEPRECATED. Use {@link KdfId}.
 */
export const Kem = {
  DhkemP256HkdfSha256: 0x0010,
  DhkemP384HkdfSha384: 0x0011,
  DhkemP521HkdfSha512: 0x0012,
  DhkemSecp256k1HkdfSha256: 0x0013,
  DhkemX25519HkdfSha256: 0x0020,
  DhkemX448HkdfSha512: 0x0021,
} as const;

export type Kem = typeof Kem[keyof typeof Kem];

/**
 * Supported Key Encapsulation Mechanism (KEM) identifiers.
 */
export const KemId = Kem;
export type KemId = typeof KemId[keyof typeof KemId];

/**
 * Supported Key Derivation Functions (KDFs).
 *
 * DEPRECATED. Use {@link KdfId}.
 */
export const Kdf = {
  HkdfSha256: 0x0001,
  HkdfSha384: 0x0002,
  HkdfSha512: 0x0003,
} as const;

export type Kdf = typeof Kdf[keyof typeof Kdf];

/**
 * Supported Key Derivation Function (KDF) identifiers.
 */
export const KdfId = Kdf;
export type KdfId = typeof KdfId[keyof typeof KdfId];

/**
 * Supported Authenticated Encryption with Associated Data (AEAD) Functions.
 *
 * DEPRECATED. Use {@link AeadId}.
 */
export const Aead = {
  Aes128Gcm: 0x0001,
  Aes256Gcm: 0x0002,
  Chacha20Poly1305: 0x0003,
  ExportOnly: 0xFFFF,
} as const;

/**
 * Supported Authenticated Encryption with Associated Data (AEAD) function identifiers.
 */
export const AeadId = Aead;
export type AeadId = typeof AeadId[keyof typeof AeadId];
