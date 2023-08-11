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
   * Generates a key pair.
   *
   * If the error occurred, throws {@link NotSupportedError}.
   *
   * @returns A key pair generated.
   * @throws {@link NotSupportedError}
   */
  generateKeyPair(): Promise<CryptoKeyPair>;

  /**
   * Derives a key pair from the byte string ikm.
   *
   * If the error occurred, throws {@link DeriveKeyPairError}.
   *
   * @param ikm An input keying material.
   * @returns A key pair derived.
   * @throws {@link DeriveKeyPairError}
   */
  deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;

  /**
   * Serializes a public key as CryptoKey to a byte string of length `Npk`.
   *
   * If the error occurred, throws {@link SerializeError}.
   *
   * @param key A CryptoKey.
   * @returns A key as bytes.
   * @throws {@link SerializeError}
   */
  serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;

  /**
   * Deserializes a public key as a byte string of length `Npk` to CryptoKey.
   *
   * If the error occurred, throws {@link DeserializeError}.
   *
   * @param key A key as bytes.
   * @returns A CryptoKey.
   * @throws {@link DeserializeError}
   */
  deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;

  /**
   * Imports a public or private key and converts to a {@link CryptoKey}.
   *
   * Since key parameters for {@link createSenderContext} or {@link createRecipientContext}
   * are {@link CryptoKey} format, you have to use this function to convert provided keys
   * to {@link CryptoKey}.
   *
   * Basically, this is a thin wrapper function of
   * [SubtleCrypto.importKey](https://www.w3.org/TR/WebCryptoAPI/#dfn-SubtleCrypto-method-importKey).
   *
   * If the error occurred, throws {@link DeserializeError}.
   *
   * @param format For now, `'raw'` and `'jwk'` are supported.
   * @param key A byte string of a raw key or A {@link JsonWebKey} object.
   * @param isPublic The indicator whether the provided key is a public key or not, which is used only for `'raw'` format.
   * @returns A public or private CryptoKey.
   * @throws {@link DeserializeError}
   */
  importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic?: boolean,
  ): Promise<CryptoKey>;

  /**
   * Generates an ephemeral, fixed-length symmetric key and
   * a fixed-length encapsulation of the key that can be decapsulated
   * by the holder of the private key corresponding to `pkR`.
   *
   * If the error occurred, throws {@link EncapError}.
   *
   * @param params A set of parameters for the sender context.
   * @returns A shared secret and an encapsulated key as the output of the encapsulation step.
   * @throws {@link EncapError}
   */
  encap(
    params: SenderContextParams,
  ): Promise<{ sharedSecret: ArrayBuffer; enc: ArrayBuffer }>;

  /**
   * Recovers the ephemeral symmetric key from its encapsulated representation `enc`.
   *
   * If the error occurred, throws {@link DecapError}.
   *
   * @param params A set of parameters for the recipient context.
   * @returns A shared secret as the output of the decapsulation step.
   * @throws {@link DecapError}
   */
  decap(params: RecipientContextParams): Promise<ArrayBuffer>;
}
