import { Dhkem, KemId } from "../../../mod_core.ts";
import { HkdfSha256 } from "./hkdfSha256.ts";
import { X25519 } from "./x25519.ts";

/**
 * The DHKEM(X25519, HKDF-SHA256) for HPKE KEM implementing {@link KemInterface}.
 *
 * This class is implemented using
 * {@link https://github.com/paulmillr/noble-curves | @noble/curves}.
 *
 * The instance of this class can be specified to the
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example Use with `@hpke/core` (`https://deno.land/x/hpke/core/mod.ts`).
 *
 * ```ts
 * import {
 *   Aes128Gcm,
 *   CipherSuite,
 *   HkdfSha256,
 * } from "https://deno.land/x/hpke/core/mod.ts";
 * import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke/x/dhkem-x25519/mod.ts";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemX25519HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new Aes128Gcm(),
 * });
 * ```
 *
 * When using `hpke-js` (`https://deno.land/x/hpke/mod.ts`), `KemId.DhkemX25519HkdfSha256`
 * can be used. You don't need to use this class.
 *
 * @example
 *
 * ```ts
 * import { AeadId, CipherSuite, KdfId, KemId } from "https://deno.land/x/hpke/mod.ts";
 *
 * const suite = new CipherSuite({
 *   kem: KemId.DhkemX25519HkdfSha256,
 *   kdf: KdfId.HkdfSha256,
 *   aead: AeadId.Aes128Gcm,
 * });
 * ```
 */
export class DhkemX25519HkdfSha256 extends Dhkem {
  /** KemId.DhkemX25519HkdfSha256 (0x0020) */
  public readonly id: KemId = KemId.DhkemX25519HkdfSha256;
  /** 32 */
  public readonly secretSize: number = 32;
  /** 32 */
  public readonly encSize: number = 32;
  /** 32 */
  public readonly publicKeySize: number = 32;
  /** 32 */
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    super(KemId.DhkemX25519HkdfSha256, new X25519(kdf), kdf);
  }
}
