import type { RecipientContextParams } from "./recipientContextParams.ts";
import type { SenderContextParams } from "./senderContextParams.ts";

import { Kem } from "../identifiers.ts";

/**
 * The KEM interface.
 */
export interface KemInterface {
  /** The KEM identifier. */
  readonly id: Kem;
  /** The length in bytes of a KEM shared secret produced by this KEM (Nsecret). */
  readonly secretSize: number;
  /** The length in bytes of an encapsulated key produced by this KEM (Nenc). */
  readonly encSize: number;
  /** The length in bytes of an encoded public key for this KEM (Npk). */
  readonly publicKeySize: number;
  /** The length in bytes of an encoded private key for this KEM (Nsk). */
  readonly privateKeySize: number;

  init(api: SubtleCrypto): void;

  /**
   * Generates a key pair.
   */
  generateKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Derives a key pair from the byte string ikm.
   */
  deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;

  /**
   * Serializes a public key as CryptoKey to a byte string of length `Npk`.
   */
  serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;

  /**
   * Deserializes a public key as a byte string of length `Npk` to CryptoKey.
   */
  deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;

  /**
   * Imports a key for the KEM.
   */
  importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey>;

  /**
   * Generates an ephemeral, fixed-length symmetric key and
   * a fixed-length encapsulation of the key that can be decapsulated
   * by the holder of the private key corresponding to `pkR`.
   */
  encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }>;

  /**
   * Recovers the ephemeral symmetric key from its encapsulated representation `enc`.
   */
  decap(params: RecipientContextParams): Promise<ArrayBuffer>;
}
