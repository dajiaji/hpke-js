/**
 * The AEAD parameters for building a encryption context.
 */
export interface AeadParams {

  /** A secret key */
  key?: CryptoKey;

  /** A base nonce */
  baseNonce?: Uint8Array;

  /** A sequence number */
  seq?: number;

  /** A secret used for the secret export interface */
  exporterSecret: ArrayBuffer;
}
