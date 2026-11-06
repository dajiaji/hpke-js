/**
 * Cipher suites to benchmark.
 *
 * Each library side is described as `[package, exportName]` for each of
 * kem / kdf / aead.
 *
 * - `hpke`: `@hpke/core` + extension packages. The all-in-one `@hpke/hpke-js`
 *   package is never used.
 * - `panva`: panva/hpke (`hpke`). Its built-in ChaCha20Poly1305 / ML-KEM /
 *   X-Wing are thin wrappers over Web Cryptography with no JS implementation,
 *   so for those primitives the pure-JS implementations of the official
 *   companion package `@panva/hpke-noble` are used instead. Everything else
 *   uses the Web Cryptography based built-ins of `hpke`, i.e. the same mix as
 *   `@hpke/core` + extensions.
 */

/** `[package, exportName]` */
export type Import = readonly [pkg: string, name: string];

export interface SuiteSpec {
  readonly kem: Import;
  readonly kdf: Import;
  readonly aead: Import;
}

export interface Suite {
  readonly id: string;
  readonly label: string;
  readonly hpke: SuiteSpec;
  readonly panva: SuiteSpec;
}

export const SUITES: readonly Suite[] = [
  {
    id: "p256-sha256-aes128gcm",
    label: "DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM",
    hpke: {
      kem: ["@hpke/core", "DhkemP256HkdfSha256"],
      kdf: ["@hpke/core", "HkdfSha256"],
      aead: ["@hpke/core", "Aes128Gcm"],
    },
    panva: {
      kem: ["hpke", "KEM_DHKEM_P256_HKDF_SHA256"],
      kdf: ["hpke", "KDF_HKDF_SHA256"],
      aead: ["hpke", "AEAD_AES_128_GCM"],
    },
  },
  {
    id: "p384-sha384-aes256gcm",
    label: "DHKEM(P-384, HKDF-SHA384) / HKDF-SHA384 / AES-256-GCM",
    hpke: {
      kem: ["@hpke/core", "DhkemP384HkdfSha384"],
      kdf: ["@hpke/core", "HkdfSha384"],
      aead: ["@hpke/core", "Aes256Gcm"],
    },
    panva: {
      kem: ["hpke", "KEM_DHKEM_P384_HKDF_SHA384"],
      kdf: ["hpke", "KDF_HKDF_SHA384"],
      aead: ["hpke", "AEAD_AES_256_GCM"],
    },
  },
  {
    id: "p521-sha512-aes256gcm",
    label: "DHKEM(P-521, HKDF-SHA512) / HKDF-SHA512 / AES-256-GCM",
    hpke: {
      kem: ["@hpke/core", "DhkemP521HkdfSha512"],
      kdf: ["@hpke/core", "HkdfSha512"],
      aead: ["@hpke/core", "Aes256Gcm"],
    },
    panva: {
      kem: ["hpke", "KEM_DHKEM_P521_HKDF_SHA512"],
      kdf: ["hpke", "KDF_HKDF_SHA512"],
      aead: ["hpke", "AEAD_AES_256_GCM"],
    },
  },
  {
    id: "x25519-sha256-aes128gcm",
    label: "DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM",
    hpke: {
      kem: ["@hpke/core", "DhkemX25519HkdfSha256"],
      kdf: ["@hpke/core", "HkdfSha256"],
      aead: ["@hpke/core", "Aes128Gcm"],
    },
    panva: {
      kem: ["hpke", "KEM_DHKEM_X25519_HKDF_SHA256"],
      kdf: ["hpke", "KDF_HKDF_SHA256"],
      aead: ["hpke", "AEAD_AES_128_GCM"],
    },
  },
  {
    id: "x25519-sha256-chacha20poly1305",
    label: "DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305",
    hpke: {
      kem: ["@hpke/core", "DhkemX25519HkdfSha256"],
      kdf: ["@hpke/core", "HkdfSha256"],
      aead: ["@hpke/chacha20poly1305", "Chacha20Poly1305"],
    },
    panva: {
      kem: ["hpke", "KEM_DHKEM_X25519_HKDF_SHA256"],
      kdf: ["hpke", "KDF_HKDF_SHA256"],
      aead: ["@panva/hpke-noble", "AEAD_ChaCha20Poly1305"],
    },
  },
  {
    id: "x448-sha512-aes256gcm",
    label: "DHKEM(X448, HKDF-SHA512) / HKDF-SHA512 / AES-256-GCM",
    hpke: {
      kem: ["@hpke/core", "DhkemX448HkdfSha512"],
      kdf: ["@hpke/core", "HkdfSha512"],
      aead: ["@hpke/core", "Aes256Gcm"],
    },
    panva: {
      kem: ["hpke", "KEM_DHKEM_X448_HKDF_SHA512"],
      kdf: ["hpke", "KDF_HKDF_SHA512"],
      aead: ["hpke", "AEAD_AES_256_GCM"],
    },
  },
  {
    id: "mlkem768-sha256-aes128gcm",
    label: "ML-KEM-768 / HKDF-SHA256 / AES-128-GCM",
    hpke: {
      kem: ["@hpke/ml-kem", "MlKem768"],
      kdf: ["@hpke/core", "HkdfSha256"],
      aead: ["@hpke/core", "Aes128Gcm"],
    },
    panva: {
      kem: ["@panva/hpke-noble", "KEM_ML_KEM_768"],
      kdf: ["hpke", "KDF_HKDF_SHA256"],
      aead: ["hpke", "AEAD_AES_128_GCM"],
    },
  },
  {
    id: "xwing-sha256-aes128gcm",
    label: "X-Wing (MLKEM768-X25519) / HKDF-SHA256 / AES-128-GCM",
    hpke: {
      kem: ["@hpke/hybridkem-x-wing", "XWing"],
      kdf: ["@hpke/core", "HkdfSha256"],
      aead: ["@hpke/core", "Aes128Gcm"],
    },
    panva: {
      kem: ["@panva/hpke-noble", "KEM_MLKEM768_X25519"],
      kdf: ["hpke", "KDF_HKDF_SHA256"],
      aead: ["hpke", "AEAD_AES_128_GCM"],
    },
  },
];
