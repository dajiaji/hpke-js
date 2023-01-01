import { Kdf } from "../identifiers.ts";

/**
 * The KDF interface.
 */
export interface KdfInterface {
  /** The KDF identifier. */
  readonly id: Kdf;
  /** The output size of the extract() function in bytes (Nh). */
  readonly hashSize: number;

  extract(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  expand(
    prk: ArrayBuffer,
    info: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer>;
}
