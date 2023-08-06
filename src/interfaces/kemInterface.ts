import type { RecipientContextParams } from "./recipientContextParams.ts";
import type { SenderContextParams } from "./senderContextParams.ts";

import { KemId } from "../identifiers.ts";

/**
 * The KEM interface.
 */
export interface KemInterface {
  /** The KEM identifier. */
  readonly id: KemId;
  /** The length in bytes of a KEM shared secret produced by this KEM (Nsecret). */
  readonly secretSize: number;
  /** The length in bytes of an encapsulated key produced by this KEM (Nenc). */
  readonly encSize: number;
  /** The length in bytes of an encoded public key for this KEM (Npk). */
  readonly publicKeySize: number;
  /** The length in bytes of an encoded private key for this KEM (Nsk). */
  readonly privateKeySize: number;

  /**
   * Initializes the instance by setting a SubtleCrypto API.
   *
   * @param api A SubtleCrypto API.
   */
  init(api: SubtleCrypto): void;

  /**
   * Generates a key pair.
   *
   * @returns A key pair.
   */
  generateKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Derives a key pair from the byte string ikm.
   *
   * @param ikm An input keying material.
   * @returns A key pair.
   */
  deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;

  /**
   * Serializes a public key as CryptoKey to a byte string of length `Npk`.
   *
   * @param key A CryptoKey.
   * @returns A key as bytes.
   */
  serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;

  /**
   * Deserializes a public key as a byte string of length `Npk` to CryptoKey.
   *
   * @param key A key as bytes.
   * @returns A CryptoKey.
   */
  deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;

  /**
   * Imports a key for the KEM.
   *
   * @param format An imput KEM key format.
   * @param key A KEM key.
   * @param isPublic The indicator whether the KEM key is public or not.
   * @returns A CryptoKey.
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
   *
   * @param params A set of parameters for the sender context.
   * @returns A shared secret and an encapsulated key as the output of the encapsulation step.
   */
  encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }>;

  /**
   * Recovers the ephemeral symmetric key from its encapsulated representation `enc`.
   *
   * @param params A set of parameters for the recipient context.
   * @returns A shared secret as the output of the decapsulation step.
   */
  decap(params: RecipientContextParams): Promise<ArrayBuffer>;
}
