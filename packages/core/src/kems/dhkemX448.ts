import { Dhkem, HkdfSha512Native, KemId } from "@hpke/common";

import { X448 } from "./dhkemPrimitives/x448.ts";

/**
 * The DHKEM(X448, HKDF-SHA512) for HPKE KEM implementing {@link KemInterface}.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   Aes256Gcm,
 *   CipherSuite,
 *   HkdfSha512,
 *   DhkemX448HkdfSha512,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemX448HkdfSha512(),
 *   kdf: new HkdfSha512(),
 *   aead: new Aes256Gcm(),
 * });
 * ```
 */
export class DhkemX448HkdfSha512 extends Dhkem {
  /** KemId.DhkemX448HkdfSha512 (0x0021) */
  override id: KemId = KemId.DhkemX448HkdfSha512;
  /** 64 */
  override secretSize: number = 64;
  /** 56 */
  override encSize: number = 56;
  /** 56 */
  override publicKeySize: number = 56;
  /** 56 */
  override privateKeySize: number = 56;

  constructor() {
    const kdf = new HkdfSha512Native();
    super(KemId.DhkemX448HkdfSha512, new X448(kdf), kdf);
  }
}
