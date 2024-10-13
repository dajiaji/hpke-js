import {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "@hpke/common";

import { CipherSuiteNative } from "./cipherSuiteNative.ts";
import {
  DhkemP256HkdfSha256Native,
  DhkemP384HkdfSha384Native,
  DhkemP521HkdfSha512Native,
} from "./kems/dhkemNative.ts";

/**
 * The Hybrid Public Key Encryption (HPKE) ciphersuite,
 * which is implemented using only
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 *
 * This class is the same as
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteNative | @hpke/core#CipherSuiteNative} as follows:
 * which supports only the ciphersuites that can be implemented on the native
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
 * Therefore, the following cryptographic algorithms are not supported for now:
 * - `DHKEM(X25519, HKDF-SHA256)`
 * - `DHKEM(X448, HKDF-SHA512)`
 * - `ChaCha20Poly1305`
 *
 * In addtion, the HKDF functions contained in this `CipherSuiteNative`
 * class can only derive keys of the same length as the `hashSize`.
 *
 * If you want to use the unsupported cryptographic algorithms
 * above or derive keys longer than the `hashSize`,
 * please use {@link https://jsr.io/@hpke/hpke-js/doc/~/CipherSuite | hpke-js#CipherSuite}.
 *
 * This class provides following functions:
 *
 * - Creates encryption contexts both for senders and recipients.
 *     - {@link createSenderContext}
 *     - {@link createRecipientContext}
 * - Provides single-shot encryption API.
 *     - {@link seal}
 *     - {@link open}
 *
 * The calling of the constructor of this class is the starting
 * point for HPKE operations for both senders and recipients.
 *
 * @example Use only ciphersuites supported by Web Cryptography API.
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 *   CipherSuite,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 *
 * @example Use a ciphersuite which is currently not supported by Web Cryptography API.
 *
 * ```ts
 * import { Aes128Gcm, HkdfSha256, CipherSuite } from "@hpke/core";
 * import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class CipherSuite extends CipherSuiteNative {}

/**
 * The DHKEM(P-256, HKDF-SHA256) for HPKE KEM implementing {@link KemInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `kem` parameter of {@link CipherSuiteParams} instead of `KemId.DhkemP256HkdfSha256`
 * as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class DhkemP256HkdfSha256 extends DhkemP256HkdfSha256Native {}

/**
 * The DHKEM(P-384, HKDF-SHA384) for HPKE KEM implementing {@link KemInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `kem` parameter of {@link CipherSuiteParams} instead of `KemId.DhkemP384HkdfSha384`
 * as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   DhkemP384HkdfSha384,
 *   HkdfSha384,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP384HkdfSha384(),
 *   kdf: new HkdfSha384(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class DhkemP384HkdfSha384 extends DhkemP384HkdfSha384Native {}

/**
 * The DHKEM(P-521, HKDF-SHA512) for HPKE KEM implementing {@link KemInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `kem` parameter of {@link CipherSuiteParams} instead of `KemId.DhkemP521HkdfSha512`
 * as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes256Gcm,
 *   CipherSuite,
 *   DhkemP521HkdfSha512,
 *   HkdfSha512,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP521HkdfSha512(),
 *   kdf: new HkdfSha512(),
 *   aead: new Aes256Gcm(),
 * });
 * ```
 */
export class DhkemP521HkdfSha512 extends DhkemP521HkdfSha512Native {}

/**
 * The HKDF-SHA256 for HPKE KDF implementing {@link KdfInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `kem` parameter of {@link CipherSuiteParams} instead of `KdfId.HkdfSha256`.
 *
 * The KDF class can only derive keys of the same length as the `hashSize`.
 * If you want to derive keys longer than the `hashSize`,
 * please use {@link https://jsr.io/@hpke/hpke-js/doc/~/CipherSuite | hpke-js#CipherSuite}.
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   DhkemP256HkdfSha256,
 *   HkdfSha256,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class HkdfSha256 extends HkdfSha256Native {}

/**
 * The HKDF-SHA384 for HPKE KDF implementing {@link KdfInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `kem` parameter of {@link CipherSuiteParams} instead of `KdfId.HkdfSha384`.
 *
 * The KDF class can only derive keys of the same length as the `hashSize`.
 * If you want to derive keys longer than the `hashSize`,
 * please use {@link https://jsr.io/@hpke/hpke-js/doc/~/CipherSuite | hpke-js#CipherSuite}.
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   DhkemP384HkdfSha384,
 *   HkdfSha384,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP384HkdfSha384(),
 *   kdf: new HkdfSha384(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class HkdfSha384 extends HkdfSha384Native {}

/**
 * The HKDF-SHA512 for HPKE KDF implementing {@link KdfInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `kem` parameter of {@link CipherSuiteParams} instead of `KdfId.HkdfSha512`.
 *
 * The KDF class can only derive keys of the same length as the `hashSize`.
 * If you want to derive keys longer than the `hashSize`,
 * please use {@link https://jsr.io/@hpke/hpke-js/doc/~/CipherSuite | hpke-js#CipherSuite}.
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes256Gcm,
 *   CipherSuite,
 *   DhkemP521HkdfSha512,
 *   HkdfSha512,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP521HkdfSha512(),
 *   kdf: new HkdfSha512(),
 *   aead: new Aes256Gcm(),
 * });
 * ```
 */
export class HkdfSha512 extends HkdfSha512Native {}
