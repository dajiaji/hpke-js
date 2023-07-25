import type { KdfInterface } from "../interfaces/kdfInterface.js";
import type { KemInterface } from "../interfaces/kemInterface.js";
import type { KemPrimitives } from "../interfaces/kemPrimitives.js";
import type { SenderContextParams } from "../interfaces/senderContextParams.js";
import type { RecipientContextParams } from "../interfaces/recipientContextParams.js";
import { Algorithm } from "../algorithm.js";
import { KemId } from "../identifiers.js";
export declare class Dhkem extends Algorithm implements KemInterface {
    readonly id: KemId;
    readonly secretSize: number;
    readonly encSize: number;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    protected _prim: KemPrimitives;
    protected _kdf: KdfInterface;
    constructor(prim: KemPrimitives, kdf: KdfInterface);
    init(api: SubtleCrypto): void;
    generateKeyPair(): Promise<CryptoKeyPair>;
    deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair>;
    serializePublicKey(key: CryptoKey): Promise<ArrayBuffer>;
    deserializePublicKey(key: ArrayBuffer): Promise<CryptoKey>;
    importKey(format: "raw" | "jwk", key: ArrayBuffer | JsonWebKey, isPublic: boolean): Promise<CryptoKey>;
    encap(params: SenderContextParams): Promise<{
        sharedSecret: ArrayBuffer;
        enc: ArrayBuffer;
    }>;
    decap(params: RecipientContextParams): Promise<ArrayBuffer>;
    private generateSharedSecret;
}
export declare class DhkemP256HkdfSha256 extends Dhkem implements KemInterface {
    readonly id: KemId;
    readonly secretSize: number;
    readonly encSize: number;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    constructor();
}
export declare class DhkemP384HkdfSha384 extends Dhkem implements KemInterface {
    readonly id: KemId;
    readonly secretSize: number;
    readonly encSize: number;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    constructor();
}
export declare class DhkemP521HkdfSha512 extends Dhkem implements KemInterface {
    readonly id: KemId;
    readonly secretSize: number;
    readonly encSize: number;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    constructor();
}
export declare class DhkemX25519HkdfSha256 extends Dhkem {
    readonly id: KemId;
    readonly secretSize: number;
    readonly encSize: number;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    constructor();
}
export declare class DhkemX448HkdfSha512 extends Dhkem implements KemInterface {
    readonly id: KemId;
    readonly secretSize: number;
    readonly encSize: number;
    readonly publicKeySize: number;
    readonly privateKeySize: number;
    constructor();
}
