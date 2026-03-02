import type { KdfInterface } from "@hpke/common";

import {
  Dhkem,
  KemId,
  SerializeError,
  XCurveDhkemPrimitives,
} from "@hpke/common";

import { x25519 } from "./primitives/x25519.ts";
import { HkdfSha256 } from "./hkdfSha256.ts";

export class X25519 extends XCurveDhkemPrimitives {
  constructor(hkdf: KdfInterface) {
    super("X25519", 32, x25519, hkdf);
  }

  public derive(sk: Uint8Array, pk: Uint8Array): Promise<Uint8Array> {
    try {
      return Promise.resolve(this._curve.getSharedSecret(sk, pk));
    } catch (e: unknown) {
      return Promise.reject(new SerializeError(e));
    }
  }
}

/**
 * The DHKEM(X25519, HKDF-SHA256) for HPKE KEM implementing {@link KemInterface}.
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
 *   Aes128Gcm,
 *   CipherSuite,
 *   HkdfSha256,
 * } from "@hpke/core";
 * import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
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
    const kdf = new HkdfSha256();
    super(KemId.DhkemX25519HkdfSha256, new X25519(kdf), kdf);
  }
}
