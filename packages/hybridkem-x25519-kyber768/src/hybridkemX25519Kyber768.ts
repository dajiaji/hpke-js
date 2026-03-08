import type { DhkemInterface } from "@hpke/common";
import { Hybridkem, KemId } from "@hpke/common";
import {
  DhkemX25519HkdfSha256 as CoreDhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { KemKyber768 } from "./kemKyber768.ts";

class DhkemX25519HkdfSha256 extends CoreDhkemX25519HkdfSha256
  implements DhkemInterface {
  public get kdf() {
    return this._kdf;
  }
}

/**
 * The Hybrid Post-Quantum KEM (X25519, Kyber768).
 *
 * This class is implemented using
 * {@link https://github.com/Argyle-Software/kyber | pqc-kyber }.
 *
 * The instance of this class can be specified to the
 * {@link https://jsr.io/@hpke/core/doc/~/CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example Use with `@hpke/core`:
 *
 * ```ts
 * import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
 * import { HybridkemX25519Kyber768 } from "@hpke/hybridkem-x25519-kyber768";
 * const suite = new CipherSuite({
 *   kem: new HybridkemX25519Kyber768(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class HybridkemX25519Kyber768 extends Hybridkem {
  override id: KemId = KemId.HybridkemX25519Kyber768;
  override name: string = "X25519Kyber25519";
  override secretSize: number = 64;
  override encSize: number = 1120;
  override publicKeySize: number = 1216;
  override privateKeySize: number = 2432;
  public readonly auth: boolean = false;

  constructor() {
    super(
      KemId.HybridkemX25519Kyber768,
      new DhkemX25519HkdfSha256(),
      new KemKyber768(),
      new HkdfSha256(),
    );
  }
}
