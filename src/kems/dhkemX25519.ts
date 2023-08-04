import { KemId } from "../identifiers.ts";
import { HkdfSha256 } from "../kdfs/hkdfSha256.ts";
import { Dhkem } from "./dhkem.ts";
import { X25519 } from "./dhkemPrimitives/x25519.ts";

/**
 * The DHKEM(X25519, HKDF-SHA256).
 *
 * @remarks
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
 * import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke/x/dhkem-x25519/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: KdfId.HkdfSha256,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 */
export class DhkemX25519HkdfSha256 extends Dhkem {
  public readonly id: KemId = KemId.DhkemX25519HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 32;
  public readonly publicKeySize: number = 32;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new X25519(kdf);
    super(prim, kdf);
  }
}
