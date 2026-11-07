// The key usages for KEM.
export const KEM_USAGES: KeyUsage[] = ["deriveBits"];

// b"dkp_prk"
export const LABEL_DKP_PRK: Uint8Array = /* @__PURE__ */ new Uint8Array([
  100,
  107,
  112,
  95,
  112,
  114,
  107,
]);

// b"sk"
export const LABEL_SK: Uint8Array = /* @__PURE__ */ new Uint8Array([115, 107]);

export interface DhkemPrimitives {
  serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;

  deserializePublicKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey>;

  serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer>;

  deserializePrivateKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey>;

  importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey>;

  generateKeyPair(): Promise<CryptoKeyPair>;

  deriveKeyPair(ikm: ArrayBufferLike | ArrayBufferView): Promise<CryptoKeyPair>;

  // DHKEM-specific function.
  derivePublicKey(key: CryptoKey): Promise<CryptoKey>;

  /**
   * Computes the raw Diffie-Hellman shared secret.
   *
   * @returns A fresh buffer whose ownership transfers to the caller.
   * `Dhkem` clears this buffer after use, including on failure. Implementations
   * must not return cached buffers or storage shared with keys or other calls.
   */
  dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer>;
}
