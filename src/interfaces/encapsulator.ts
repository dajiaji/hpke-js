/**
 * The sender specific interface for an encryption context.
 */
export interface Encapsulator {
  /** The encapsulated key generated by the sender. */
  enc: ArrayBuffer;
}
