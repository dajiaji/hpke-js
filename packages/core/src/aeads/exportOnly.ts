import type { AeadEncryptionContext, AeadInterface } from "@hpke/common";
import { AeadId, NotSupportedError } from "@hpke/common";

/**
 * The ExportOnly mode for HPKE AEAD implementing {@link AeadInterface}.
 *
 * When using `@hpke/core`, the instance of this class must be specified
 * to the `aead` parameter of {@link CipherSuiteParams} instead of `AeadId.ExportOnly`
 * as follows:
 *
 * @example
 *
 * ```ts
 * import {
 *   CipherSuite,
 *   DhkemP256HkdfSha256,
 *   ExportOnly,
 *   HkdfSha256,
 * } from "@hpke/core";
 *
 * const suite = new CipherSuite({
 *   kem: new DhkemP256HkdfSha256(),
 *   kdf: new HkdfSha256(),
 *   aead: new ExportOnly(),
 * });
 * ```
 */
export class ExportOnly implements AeadInterface {
  public readonly id: AeadId = AeadId.ExportOnly;
  public readonly keySize: number = 0;
  public readonly nonceSize: number = 0;
  public readonly tagSize: number = 0;

  public createEncryptionContext(_key: ArrayBuffer): AeadEncryptionContext {
    throw new NotSupportedError("Export only");
  }
}
