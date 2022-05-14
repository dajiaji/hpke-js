export interface KemPrimitives {

  serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;

  deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;

  derivePublicKey(key: CryptoKey): Promise<CryptoKey>;

  generateKeyPair(): Promise<CryptoKeyPair>;

  deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;

  deriveKey(ikm: ArrayBuffer): Promise<ArrayBuffer>;

  dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer>;
}
