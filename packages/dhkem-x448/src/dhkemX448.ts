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
 * {@link https://deno.land/x/hpke/core/mod.ts?s=CipherSuiteParams | CipherSuiteParams} as follows:
 *
 * @example Use with `hpke-js` (`https://deno.land/x/hpke/mod.ts`).
 *
 * ```ts
 * import { CipherSuite, AeadId, KdfId } from "https://deno.land/x/hpke/mod.ts";
 * import { DhkemX448HkdfSha512 } from "https://deno.land/x/hpke/x/dhkem-x448/mod.ts";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemX448HkdfSha512(),
 *   kdf: KdfId.HkdfSha512,
 *   aead: AeadId.Aes256Gcm,
 * });
 * ```
 *
 * @example Use with `@hpke/core` (`https://deno.land/x/hpke/core/mod.ts`).
 *
 * ```ts
 * import {
 *   Aes256Gcm,
 *   CipherSuite,
 *   HkdfSha512,
 * } from "https://deno.land/x/hpke/core/mod.ts";
 * import { DhkemX448HkdfSha512 } from "https://deno.land/x/hpke/x/dhkem-x448/mod.ts";
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
  public readonly id: KemId = KemId.DhkemX448HkdfSha512;
  /** 64 */
  public readonly secretSize: number = 64;
  /** 56 */
  public readonly encSize: number = 56;
  /** 56 */
  public readonly publicKeySize: number = 56;
  /** 56 */
  public readonly privateKeySize: number = 56;

  constructor() {
    const kdf = new HkdfSha512();
    super(KemId.DhkemX448HkdfSha512, new X448(kdf), kdf);
  }
}
