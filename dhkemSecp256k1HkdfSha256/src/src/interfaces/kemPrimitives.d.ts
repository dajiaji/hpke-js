export interface KemPrimitives {
    init(api: SubtleCrypto): void;
    serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;
    deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;
    importKey(format: "raw" | "jwk", key: ArrayBuffer | JsonWebKey, isPublic: boolean): Promise<CryptoKey>;
    derivePublicKey(key: CryptoKey): Promise<CryptoKey>;
    generateKeyPair(): Promise<CryptoKeyPair>;
    deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;
    dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer>;
}
