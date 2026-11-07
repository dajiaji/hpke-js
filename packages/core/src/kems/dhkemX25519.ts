import {
  Dhkem,
  HkdfSha256Native,
  X_CURVE_X25519,
  XCurveNativeDhkemPrimitives,
} from "@hpke/common";
import type { KemId } from "@hpke/common";

/**
 * The DHKEM(X25519, HKDF-SHA256) for HPKE KEM implementing {@link KemInterface}.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   HkdfSha256,
 *   DhkemX25519HkdfSha256,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class DhkemX25519HkdfSha256 extends Dhkem {
  /** KemId.DhkemX25519HkdfSha256 (0x0020) */
  override id: KemId = 0x0020; // KemId.DhkemX25519HkdfSha256
  /** 32 */
  override secretSize: number = 32;
  /** 32 */
  override encSize: number = 32;
  /** 32 */
  override publicKeySize: number = 32;
  /** 32 */
  override privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256Native();
    super(
      0x0020, /* KemId.DhkemX25519HkdfSha256 */
      new XCurveNativeDhkemPrimitives(X_CURVE_X25519, kdf),
      kdf,
    );
  }
}
