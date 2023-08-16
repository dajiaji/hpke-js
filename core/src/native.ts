import { CipherSuiteNative } from "../../src/cipherSuiteNative.ts";
import {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "../../src/kdfs/hkdf.ts";
import {
  DhkemP256HkdfSha256Native,
  DhkemP384HkdfSha384Native,
  DhkemP521HkdfSha512Native,
} from "../../src/kems/dhkemNative.ts";

/**
 * The Hybrid Public Key Encryption (HPKE) ciphersuite,
 * which is implemented using only
 * {@link https://www.w3.org/TR/WebCryptoAPI/ | Web Cryptography API}.
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
 * - Creates encryption contexts both for senders and recipients.
 *   - {@link createSenderContext}
 *   - {@link createRecipientContext}
 * - Provides single-shot encryption API.
 *   - {@link seal}
 *   - {@link open}
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
 * } from "http://deno.land/x/hpke/core/mod.ts";
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
 * import { Aes128Gcm, HkdfSha256, CipherSuite } from "http://deno.land/x/hpke/core/mod.ts";
 * import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke/x/dhkem-x25519/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class CipherSuite extends CipherSuiteNative {}

export class DhkemP256HkdfSha256 extends DhkemP256HkdfSha256Native {}
export class DhkemP384HkdfSha384 extends DhkemP384HkdfSha384Native {}
export class DhkemP521HkdfSha512 extends DhkemP521HkdfSha512Native {}
export class HkdfSha256 extends HkdfSha256Native {}
export class HkdfSha384 extends HkdfSha384Native {}
export class HkdfSha512 extends HkdfSha512Native {}
