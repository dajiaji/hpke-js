import { AeadId } from "../identifiers.ts";

/**
 * The AEAD interface.
 */
export interface AeadKey {
  /** The AEAD identifier. */
  readonly id: AeadId;
  /** The length in bytes of an AEAD key (Nk). */
  readonly keySize: number;
  /** The length in bytes of an AEAD nonce (Nn). */
  readonly nonceSize: number;
  /** The length in bytes of an AEAD authentication tag (Nt). */
  readonly tagSize: number;

  /**
   * Initializes the key by setting the SubtleCrypto.
   */
  init(api: SubtleCrypto): void;

  /**
   * Encrypts data with initial vector and additional authenticated data.
   */
  seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  /**
   * Decrypts data with initial vector and additional authenticated data.
   */
  open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer>;
}
