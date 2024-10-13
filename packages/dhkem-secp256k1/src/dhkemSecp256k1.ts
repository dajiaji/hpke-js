import { Dhkem, KemId } from "@hpke/common";
import { HkdfSha256 } from "@hpke/dhkem-x25519";

import { Secp256k1 } from "./secp256k1.ts";

/**
 * The DHKEM(secp256k1, HKDF-SHA256) for HPKE KEM implementing {@link KemInterface}.
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-curves | @noble/curves}.
 *
 * The public keys are assumed to be compressed.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example Use with `@hpke/core`:
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   HkdfSha256,
 * } from "@hpke/core";
 * import { DhkemSecp256k1HkdfSha256 } from "@hpke/dhkem-secp256k1";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemSecp256k1HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 *
 * @experimental Note that it is experimental and not standardized.
 */
export class DhkemSecp256k1HkdfSha256 extends Dhkem {
  /** KemId.DhkemSecp256k1HkdfSha256 (0x0013) EXPERIMENTAL */
  override id: KemId = KemId.DhkemSecp256k1HkdfSha256;
  /** 32 */
  override secretSize: number = 32;
  /** 33 */
  override encSize: number = 33;
  /** 33 */
  override publicKeySize: number = 33;
  /** 32 */
  override privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    super(KemId.DhkemSecp256k1HkdfSha256, new Secp256k1(kdf), kdf);
  }
}
