/**
 * Supported HPKE modes.
 */
export const Mode = {
  Base: 0x00,
  Psk: 0x01,
  Auth: 0x02,
  AuthPsk: 0x03,
} as const;

/**
 * The type of the Supported HPKE modes.
 */
export type Mode = typeof Mode[keyof typeof Mode];

/**
 * Supported Key Encapsulation Mechanism (KEM) identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export const Kem = {
  DhkemP256HkdfSha256: 0x0010,
  DhkemP384HkdfSha384: 0x0011,
  DhkemP521HkdfSha512: 0x0012,
  DhkemSecp256k1HkdfSha256: 0x0013,
  DhkemX25519HkdfSha256: 0x0020,
  DhkemX448HkdfSha512: 0x0021,
} as const;

/**
 * The type of the supported KEM identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export type Kem = typeof Kem[keyof typeof Kem];

/**
 * Supported Key Encapsulation Mechanism (KEM) identifiers.
 */
export const KemId = Kem;

/**
 * The type of the supported KEM identifiers.
 */
export type KemId = typeof KemId[keyof typeof KemId];

/**
 * Supported Key Derivation Function (KDF) identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export const Kdf = {
  HkdfSha256: 0x0001,
  HkdfSha384: 0x0002,
  HkdfSha512: 0x0003,
} as const;

/**
 * The type of the supported KDF identifiers.
 *
 * @deprecated Use {@link KdfId} instead.
 */
export type Kdf = typeof Kdf[keyof typeof Kdf];

/**
 * Supported Key Derivation Function (KDF) identifiers.
 */
export const KdfId = Kdf;

/**
 * The type of the supported KDF identifiers.
 */
export type KdfId = typeof KdfId[keyof typeof KdfId];

/**
 * Supported Authenticated Encryption with Associated Data (AEAD) identifiers.
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
 * The type of the supported AEAD identifiers.
 *
 * @deprecated Use {@link AeadId} instead.
 */
export type Aead = typeof Aead[keyof typeof Aead];

/**
 * Supported Authenticated Encryption with Associated Data (AEAD) identifiers.
 */
export const AeadId = Aead;

/**
 * The type of the supported AEAD identifiers.
 */
export type AeadId = typeof AeadId[keyof typeof AeadId];
