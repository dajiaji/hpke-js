import { KemId } from "../identifiers.ts";
import { HkdfSha256 } from "../kdfs/hkdfSha256.ts";
import { Dhkem } from "./dhkem.ts";
import { Secp256k1 } from "./dhkemPrimitives/secp256k1.ts";

/**
 * The DHKEM(secp256k1, HKDF-SHA256).
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-curves | @noble/curves}.
 *
 * The public keys are assumed to be compressed.
 *
 * The instance of this class can be specified to the
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example
 *
 * ```ts
 * import { KdfId, AeadId, CipherSuite } from "http://deno.land/x/hpke/core/mod.ts";
 * import { DhkemSecp256k1HkdfSha256} from "https://deno.land/x/hpke/x/dhkem-secp256k1/mod.ts";
 * const suite = new CipherSuite({
 *   kem: new DhkemSecp256k1HkdfSha256(),
 *   kdf: KdfId.HkdfSha256,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 *
 * @experimental Note that it is experimental and not standardized.
 */
export class DhkemSecp256k1HkdfSha256 extends Dhkem {
  public readonly id: KemId = KemId.DhkemSecp256k1HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 33;
  public readonly publicKeySize: number = 33;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    super(KemId.DhkemSecp256k1HkdfSha256, new Secp256k1(kdf), kdf);
  }
}
