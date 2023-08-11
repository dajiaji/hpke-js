import { KdfId } from "../identifiers.ts";

/**
 * The KDF interface.
 */
export interface KdfInterface {
  /** The KDF identifier. */
  readonly id: KdfId;
  /** The output size of the extract() function in bytes (Nh). */
  readonly hashSize: number;

  /**
   * Initializes the instance by setting a `suite_id` defined in RFC9180.
   *
   * @param suiteId A `suite_id` defined in RFC9180.
   */
  init(suiteId: Uint8Array): void;

  /**
   * Builds a labeled input keying material.
   *
   * @param label A byte string indicating the cryptographic context/operation.
   * @param info An additional byte string.
   * @returns An input keying material as bytes.
   */
  buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array;

  /**
   * Builds a labeled info string.
   *
   * @param label A byte string indicating the cryptographic context/operation.
   * @param info An additional byte string.
   * @param len The length of the output byte string.
   * @returns An info string as bytes.
   */
  buildLabeledInfo(
    label: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Uint8Array;

  /**
   * Extracts a pseudorandom key of fixed length (Nh) bytes.
   *
   * @param salt An additional random byte string.
   * @param ikm An input keying material
   * @returns A pseudorandom key as bytes.
   */
  extract(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  /**
   * Expands a pseudorandom key `prk`.
   *
   * @param prk A pseudorandom key.
   * @param info An additional byte string.
   * @param len The length in bytes of the output keying material.
   * @returns An output keying material as bytes.
   */
  expand(
    prk: ArrayBuffer,
    info: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer>;

  /**
   * Extracts a pseudorandom key and expand it to a specified length keying material.
   *
   * @param salt An additional random byte string.
   * @param ikm An input keying material
   * @param info An additional byte string.
   * @param len The length in bytes of the output keying material.
   * @returns An output keying material as bytes.
   */
  extractAndExpand(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
    info: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer>;

  /**
   * Extracts a pseudorandom key with label.
   *
   * @param salt An additional random byte string.
   * @param label A byte string indicating the cryptographic context/operation.
   * @param ikm An input keying material
   * @returns A pseudorandom key as bytes.
   */
  labeledExtract(
    salt: ArrayBuffer,
    label: Uint8Array,
    ikm: Uint8Array,
  ): Promise<ArrayBuffer>;

  /**
   * Extracts a pseudorandom key with label.
   *
   * @param prk A pseudorandom key.
   * @param label A byte string indicating the cryptographic context/operation.
   * @param info An additional byte string.
   * @param len The length in bytes of the output keying material.
   * @returns An output keying material as bytes.
   */
  labeledExpand(
    prk: ArrayBuffer,
    label: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Promise<ArrayBuffer>;
}
