import type { KemPrimitives } from "../../interfaces/kemPrimitives.js";
import type { KdfInterface } from "../../interfaces/kdfInterface.js";
import { Algorithm } from "../../algorithm.js";
import { KemId } from "../../identifiers.js";
export declare class Ec extends Algorithm implements KemPrimitives {
    private _hkdf;
    private _alg;
    private _nPk;
    private _nSk;
    private _nDh;
    private _order;
    private _bitmask;
    private _pkcs8AlgId;
    constructor(kem: KemId, hkdf: KdfInterface);
    serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;
    deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;
    importKey(format: "raw" | "jwk", key: ArrayBuffer | JsonWebKey, isPublic: boolean): Promise<CryptoKey>;
    private _importRawKey;
    private _importJWK;
    derivePublicKey(key: CryptoKey): Promise<CryptoKey>;
    generateKeyPair(): Promise<CryptoKeyPair>;
    deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;
    dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer>;
}
