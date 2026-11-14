import type { KdfInterface } from "./kdfInterface.ts";

/**
 * The one-stage KDF interface defined in
 * [draft-ietf-hpke-hpke](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/).
 *
 * A one-stage KDF provides a single `Derive()` function instead of the
 * `Extract()` and `Expand()` functions of a two-stage KDF such as HKDF. The
 * two-stage functions inherited from {@link KdfInterface} are not supported
 * and throw `NotSupportedError`.
 */
export interface OneStageKdfInterface extends KdfInterface {
  /**
   * Derives a keying material of `len` bytes from the input keying material.
   *
   * @param ikm An input keying material.
   * @param len The length in bytes of the output keying material.
   * @returns An output keying material as bytes.
   */
  derive(
    ikm: ArrayBufferLike | ArrayBufferView,
    len: number,
  ): Promise<ArrayBuffer>;

  /**
   * Derives a keying material of `len` bytes with label, bound to the
   * `suite_id` set by `init()`.
   *
   * @param ikm An input keying material.
   * @param label A byte string indicating the cryptographic context/operation.
   * @param context An additional byte string.
   * @param len The length in bytes of the output keying material.
   * @returns An output keying material as bytes.
   */
  labeledDerive(
    ikm: ArrayBufferLike | ArrayBufferView,
    label: Uint8Array,
    context: Uint8Array,
    len: number,
  ): Promise<ArrayBuffer>;
}
