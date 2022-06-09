/**
 * Supported HPKE modes.
 */
export var Mode;
(function (Mode) {
    Mode[Mode["Base"] = 0] = "Base";
    Mode[Mode["Psk"] = 1] = "Psk";
    Mode[Mode["Auth"] = 2] = "Auth";
    Mode[Mode["AuthPsk"] = 3] = "AuthPsk";
})(Mode || (Mode = {}));
/**
 * Supported Key Encapsulation Mechanisms (KEMs).
 */
export var Kem;
(function (Kem) {
    /** DHKEM (P-256, HKDF-SHA256). */
    Kem[Kem["DhkemP256HkdfSha256"] = 16] = "DhkemP256HkdfSha256";
    /** DHKEM (P-384, HKDF-SHA384). */
    Kem[Kem["DhkemP384HkdfSha384"] = 17] = "DhkemP384HkdfSha384";
    /** DHKEM (P-521, HKDF-SHA512). */
    Kem[Kem["DhkemP521HkdfSha512"] = 18] = "DhkemP521HkdfSha512";
    /** DHKEM (X25519, HKDF-SHA256) */
    Kem[Kem["DhkemX25519HkdfSha256"] = 32] = "DhkemX25519HkdfSha256";
    /** DHKEM (X448, HKDF-SHA512) */
    Kem[Kem["DhkemX448HkdfSha512"] = 33] = "DhkemX448HkdfSha512";
})(Kem || (Kem = {}));
/**
 * Supported Key Derivation Functions (KDFs).
 */
export var Kdf;
(function (Kdf) {
    /** HKDF-SHA256. */
    Kdf[Kdf["HkdfSha256"] = 1] = "HkdfSha256";
    /** HKDF-SHA384. */
    Kdf[Kdf["HkdfSha384"] = 2] = "HkdfSha384";
    /** HKDF-SHA512. */
    Kdf[Kdf["HkdfSha512"] = 3] = "HkdfSha512";
})(Kdf || (Kdf = {}));
/**
 * Supported Authenticated Encryption with Associated Data (AEAD) Functions.
 */
export var Aead;
(function (Aead) {
    /** AES-128-GCM. */
    Aead[Aead["Aes128Gcm"] = 1] = "Aes128Gcm";
    /** AES-256-GCM. */
    Aead[Aead["Aes256Gcm"] = 2] = "Aes256Gcm";
    /** ChaCha20Poly1305. */
    Aead[Aead["Chacha20Poly1305"] = 3] = "Chacha20Poly1305";
    /**
     * Export-only mode for applications that only use the export() function
     * to get secrets for AEAD.
     */
    Aead[Aead["ExportOnly"] = 65535] = "ExportOnly";
})(Aead || (Aead = {}));
