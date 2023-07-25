/**
 * Supported HPKE modes.
 */
export declare const Mode: {
    readonly Base: 0;
    readonly Psk: 1;
    readonly Auth: 2;
    readonly AuthPsk: 3;
};
export type Mode = typeof Mode[keyof typeof Mode];
/**
 * Supported Key Encapsulation Mechanisms (KEMs).
 *
 * DEPRECATED. Use KdfId.
 */
export declare const Kem: {
    /** DHKEM (P-256, HKDF-SHA256). */
    readonly DhkemP256HkdfSha256: 16;
    /** DHKEM (P-384, HKDF-SHA384). */
    readonly DhkemP384HkdfSha384: 17;
    /** DHKEM (P-521, HKDF-SHA512). */
    readonly DhkemP521HkdfSha512: 18;
    /** DHKEM (secp256k1, HKDF-SHA256). EXPERIMENTAL/DEPRECATED. The KEM id can be changed in the standardization process. */
    readonly DhkemSecp256K1HkdfSha256: 19;
    /** DHKEM (secp256k1, HKDF-SHA256). EXPERIMENTAL. The KEM id can be changed in the standardization process. */
    readonly DhkemSecp256k1HkdfSha256: 19;
    /** DHKEM (X25519, HKDF-SHA256) */
    readonly DhkemX25519HkdfSha256: 32;
    /** DHKEM (X448, HKDF-SHA512) */
    readonly DhkemX448HkdfSha512: 33;
};
export type Kem = typeof Kem[keyof typeof Kem];
/**
 * Supported Key Encapsulation Mechanism (KEM) identifiers.
 */
export declare const KemId: {
    /** DHKEM (P-256, HKDF-SHA256). */
    readonly DhkemP256HkdfSha256: 16;
    /** DHKEM (P-384, HKDF-SHA384). */
    readonly DhkemP384HkdfSha384: 17;
    /** DHKEM (P-521, HKDF-SHA512). */
    readonly DhkemP521HkdfSha512: 18;
    /** DHKEM (secp256k1, HKDF-SHA256). EXPERIMENTAL/DEPRECATED. The KEM id can be changed in the standardization process. */
    readonly DhkemSecp256K1HkdfSha256: 19;
    /** DHKEM (secp256k1, HKDF-SHA256). EXPERIMENTAL. The KEM id can be changed in the standardization process. */
    readonly DhkemSecp256k1HkdfSha256: 19;
    /** DHKEM (X25519, HKDF-SHA256) */
    readonly DhkemX25519HkdfSha256: 32;
    /** DHKEM (X448, HKDF-SHA512) */
    readonly DhkemX448HkdfSha512: 33;
};
export type KemId = typeof KemId[keyof typeof KemId];
/**
 * Supported Key Derivation Functions (KDFs).
 *
 * DEPRECATED. Use KdfId.
 */
export declare const Kdf: {
    /** HKDF-SHA256. */
    readonly HkdfSha256: 1;
    /** HKDF-SHA384. */
    readonly HkdfSha384: 2;
    /** HKDF-SHA512. */
    readonly HkdfSha512: 3;
};
export type Kdf = typeof Kdf[keyof typeof Kdf];
/**
 * Supported Key Derivation Function (KDF) identifiers.
 */
export declare const KdfId: {
    /** HKDF-SHA256. */
    readonly HkdfSha256: 1;
    /** HKDF-SHA384. */
    readonly HkdfSha384: 2;
    /** HKDF-SHA512. */
    readonly HkdfSha512: 3;
};
export type KdfId = typeof KdfId[keyof typeof KdfId];
/**
 * Supported Authenticated Encryption with Associated Data (AEAD) Functions.
 *
 * DEPRECATED. Use AeadId.
 */
export declare const Aead: {
    /** AES-128-GCM. */
    readonly Aes128Gcm: 1;
    /** AES-256-GCM. */
    readonly Aes256Gcm: 2;
    /** ChaCha20Poly1305. */
    readonly Chacha20Poly1305: 3;
    /**
     * Export-only mode for applications that only use the export() function
     * to get secrets for AEAD.
     */
    readonly ExportOnly: 65535;
};
/**
 * Supported Authenticated Encryption with Associated Data (AEAD) function identifiers.
 */
export declare const AeadId: {
    /** AES-128-GCM. */
    readonly Aes128Gcm: 1;
    /** AES-256-GCM. */
    readonly Aes256Gcm: 2;
    /** ChaCha20Poly1305. */
    readonly Chacha20Poly1305: 3;
    /**
     * Export-only mode for applications that only use the export() function
     * to get secrets for AEAD.
     */
    readonly ExportOnly: 65535;
};
export type AeadId = typeof AeadId[keyof typeof AeadId];
