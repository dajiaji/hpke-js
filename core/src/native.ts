import { CipherSuiteNative } from "../../src/cipherSuiteNative.ts";

/**
 * The Hybrid Public Key Encryption (HPKE) ciphersuite,
 * which is implemented using only
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 *
 * @remarks
 *
 * This class is the same as
 * {@link https://deno.land/x/hpke/mod.ts?s=CipherSuiteNative | @hpke/core#CipherSuiteNative },
 * which supports only the ciphersuites that can be implemented on the native
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 * Therefore, the following cryptographic algorithms are not supported for now:
 *   - DHKEM(X25519, HKDF-SHA256)
 *   - DHKEM(X448, HKDF-SHA512)
 *   - ChaCha20Poly1305
 *
 * In addtion, the HKDF functions contained in this `CipherSuiteNative`
 * class can only derive keys of the same length as the `hashSize`.
 *
 * If you want to use the unsupported cryptographic algorithms
 * above or derive keys longer than the `hashSize`,
 * please use {@link https://deno.land/x/hpke/mod.ts?s=CipherSuite | hpke-js#CipherSuite}.
 *
 * This class provides following functions:
 *
 * - [DEPRECATED] Generates a key pair for the cipher suite.
 * - [DEPRECATED] Derives a key pair for the cipher suite.
 * - [DEPRECATED] Imports and converts a key to a CryptoKey.
 * - Creates an encryption context both for senders and recipients.
 * - Encrypts a message as a single-shot API.
 * - Decrypts an encrypted message as as single-shot API.
 *
 * The calling of the constructor of this class is the starting
 * point for HPKE operations for both senders and recipients.
 *
 * @example Use only ciphersuites supported by Web Cryptography API.
 * ```ts
 * import { KemId, KdfId, AeadId, CipherSuite } from "http://deno.land/x/hpke/core/mod.ts";
 * const suite = new CipherSuite({
 *   kem: KemId.DhkemP256HkdfSha256,
 *   kdf: KdfId.HkdfSha256,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 *
 * @example Use a ciphersuite which is currently not supported by Web Cryptography API.
 * ```ts
 * import { KdfId, AeadId, CipherSuiteNative } from "http://deno.land/x/hpke/core/mod.ts";
 * import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke/x/dhkem-x25519/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: KdfId.HkdfSha256,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 */
export class CipherSuite extends CipherSuiteNative {}
