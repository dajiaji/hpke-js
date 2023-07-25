import type { KemPrimitives } from "../../interfaces/kemPrimitives.js";
import type { KdfInterface } from "../../interfaces/kdfInterface.js";
import { Algorithm } from "../../algorithm.js";
export declare class X448 extends Algorithm implements KemPrimitives {
    private _hkdf;
    private _nPk;
    private _nSk;
    constructor(hkdf: KdfInterface);
    serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;
    deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;
    importKey(format: "raw" | "jwk", key: ArrayBuffer | JsonWebKey, isPublic: boolean): Promise<CryptoKey>;
    derivePublicKey(key: CryptoKey): Promise<CryptoKey>;
    generateKeyPair(): Promise<CryptoKeyPair>;
    deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;
    dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer>;
    private _serializePublicKey;
    private _deserializePublicKey;
    private _importRawKey;
    private _importJWK;
    private _derivePublicKey;
    private _dh;
}
