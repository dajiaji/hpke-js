/**
 * The response of the single-shot seal API.
 */
export interface CipherSuiteSealResponse {
  /** The ciphertext as bytes. */
  ct: ArrayBuffer;
  /** The encapsulated key. */
  enc: ArrayBuffer;
}
