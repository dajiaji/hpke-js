import { KemId } from "../identifiers.ts";
import { HkdfSha512 } from "../kdfs/hkdfSha512.ts";
import { Dhkem } from "./dhkem.ts";
import { X448 } from "./dhkemPrimitives/x448.ts";

/**
 * The DHKEM(X448, HKDF-SHA512).
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-curves | @noble/curves}.
 *
 * The instance of this class can be specified to the
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 * ```ts
 * import { KdfId, AeadId, CipherSuite } from "http://deno.land/x/hpke/core/mod.ts";
 * import { DhkemX448HkdfSha512 } from "https://deno.land/x/hpke/x/dhkem-x448/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new DhkemX448HkdfSha512(),
 *   kdf: KdfId.HkdfSha512,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 */
export class DhkemX448HkdfSha512 extends Dhkem {
  public readonly id: KemId = KemId.DhkemX448HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 56;
  public readonly publicKeySize: number = 56;
  public readonly privateKeySize: number = 56;

  constructor() {
    const kdf = new HkdfSha512();
    super(KemId.DhkemX448HkdfSha512, new X448(kdf), kdf);
  }
}
