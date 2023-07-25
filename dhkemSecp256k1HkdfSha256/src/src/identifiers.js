/**
 * Supported HPKE modes.
 */
export const Mode = {
    Base: 0x00,
    Psk: 0x01,
    Auth: 0x02,
    AuthPsk: 0x03,
};
/**
 * Supported Key Encapsulation Mechanisms (KEMs).
 *
 * DEPRECATED. Use KdfId.
 */
export const Kem = {
    /** DHKEM (P-256, HKDF-SHA256). */
    DhkemP256HkdfSha256: 0x0010,
    /** DHKEM (P-384, HKDF-SHA384). */
    DhkemP384HkdfSha384: 0x0011,
    /** DHKEM (P-521, HKDF-SHA512). */
    DhkemP521HkdfSha512: 0x0012,
    /** DHKEM (secp256k1, HKDF-SHA256). EXPERIMENTAL/DEPRECATED. The KEM id can be changed in the standardization process. */
    DhkemSecp256K1HkdfSha256: 0x0013,
    /** DHKEM (secp256k1, HKDF-SHA256). EXPERIMENTAL. The KEM id can be changed in the standardization process. */
    DhkemSecp256k1HkdfSha256: 0x0013,
    /** DHKEM (X25519, HKDF-SHA256) */
    DhkemX25519HkdfSha256: 0x0020,
    /** DHKEM (X448, HKDF-SHA512) */
    DhkemX448HkdfSha512: 0x0021,
};
/**
 * Supported Key Encapsulation Mechanism (KEM) identifiers.
 */
export const KemId = Kem;
/**
 * Supported Key Derivation Functions (KDFs).
 *
 * DEPRECATED. Use KdfId.
 */
export const Kdf = {
    /** HKDF-SHA256. */
    HkdfSha256: 0x0001,
    /** HKDF-SHA384. */
    HkdfSha384: 0x0002,
    /** HKDF-SHA512. */
    HkdfSha512: 0x0003,
};
/**
 * Supported Key Derivation Function (KDF) identifiers.
 */
export const KdfId = Kdf;
/**
 * Supported Authenticated Encryption with Associated Data (AEAD) Functions.
 *
 * DEPRECATED. Use AeadId.
 */
export const Aead = {
    /** AES-128-GCM. */
    Aes128Gcm: 0x0001,
    /** AES-256-GCM. */
    Aes256Gcm: 0x0002,
    /** ChaCha20Poly1305. */
    Chacha20Poly1305: 0x0003,
    /**
     * Export-only mode for applications that only use the export() function
     * to get secrets for AEAD.
     */
    ExportOnly: 0xFFFF,
};
/**
 * Supported Authenticated Encryption with Associated Data (AEAD) function identifiers.
 */
export const AeadId = Aead;
