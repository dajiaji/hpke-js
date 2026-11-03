/**
 * A CBOR value that can be encoded/decoded by the minimal CBOR codec.
 *
 * Supported types: unsigned integer, negative integer, byte string,
 * text string, array, map (with integer or text keys), tag, and null.
 */
export type CborValue =
  | number
  | Uint8Array
  | string
  | CborValue[]
  | Map<CborValue, CborValue>
  | CborTag
  | null;

/** A tagged CBOR data item (major type 6). */
export class CborTag {
  constructor(
    /** The tag number. */
    readonly tag: number,
    /** The tag content. */
    readonly value: CborValue,
  ) {}
}
