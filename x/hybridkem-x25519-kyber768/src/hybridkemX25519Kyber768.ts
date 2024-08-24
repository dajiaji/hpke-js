import type { DhkemInterface } from "@hpke/core";

import { Dhkem, Hybridkem, KemId } from "@hpke/core";
import { HkdfSha256, X25519 } from "@hpke/dhkem-x25519";

import { KemKyber768 } from "./kemKyber768.ts";

class DhkemX25519HkdfSha256 extends Dhkem implements DhkemInterface {
  public readonly id: KemId = KemId.DhkemX25519HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 32;
  public readonly publicKeySize: number = 32;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    super(KemId.DhkemX25519HkdfSha256, new X25519(kdf), kdf);
  }

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
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import { Aes128Gcm, CipherSuite, HkdfSha256 } from "http://deno.land/x/hpke/core/mod.ts";
 * import { HybridkemX25519Kyber768 } from "https://deno.land/x/hpke/x/hybridkem-x25519-kyber768/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new HybridkemX25519Kyber768(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 */
export class HybridkemX25519Kyber768 extends Hybridkem {
  public readonly id: KemId = KemId.HybridkemX25519Kyber768;
  public readonly name: string = "X25519Kyber25519";
  public readonly secretSize: number = 64;
  public readonly encSize: number = 1120;
  public readonly publicKeySize: number = 1216;
  public readonly privateKeySize: number = 2432;
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
