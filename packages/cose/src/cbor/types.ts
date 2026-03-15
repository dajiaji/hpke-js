/**
 * A CBOR value that can be encoded/decoded by the minimal CBOR codec.
 *
 * Supported types: unsigned integer, negative integer, byte string,
 * text string, array, map (with integer or text keys), and null.
 */
export type CborValue =
  | number
  | Uint8Array
  | string
  | CborValue[]
  | Map<CborValue, CborValue>
  | null;
