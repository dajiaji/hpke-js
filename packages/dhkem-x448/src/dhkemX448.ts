import { Dhkem, KemId } from "@hpke/common";
import { HkdfSha512 } from "./hkdfSha512.ts";
import { X448 } from "./x448.ts";

/**
 * The DHKEM(X448, HKDF-SHA512) for HPKE KEM implementing {@link KemInterface}.
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-curves | @noble/curves}.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example Use with `@hpke/core`:
 *
 * ```ts
 * import {
 *   Aes256Gcm,
 *   CipherSuite,
 *   HkdfSha512,
 * } from "@hpke/core";
 * import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
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
    const kdf = new HkdfSha512();
    super(KemId.DhkemX448HkdfSha512, new X448(kdf), kdf);
  }
}
