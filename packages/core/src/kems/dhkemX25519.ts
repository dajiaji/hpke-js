import { Dhkem, HkdfSha256Native, KemId } from "@hpke/common";

import { X25519 } from "./dhkemPrimitives/x25519.ts";

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
  override id: KemId = KemId.DhkemX25519HkdfSha256;
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
    super(KemId.DhkemX25519HkdfSha256, new X25519(kdf), kdf);
  }
}
