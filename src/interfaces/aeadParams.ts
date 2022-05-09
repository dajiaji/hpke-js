/**
 * The AEAD parameters for building a encryption context.
 */
export interface AeadParams {

  /** The algorithm identifier */
  alg: string;

  /** The length in bytes of a key for the algorithm */
  nK: number;

  /** The length in bytes of a nonce for the algorithm */
  nN: number;

  /** The length in bytes of an authentication tag for the algorithm */
  nT: number;

  /** A secret used for the secret export interface */
  exporterSecret: ArrayBuffer;

  /** A secret key */
  key?: CryptoKey;

  /** A base nonce */
  baseNonce?: Uint8Array;

  /** A sequence number */
  seq?: number;
}
