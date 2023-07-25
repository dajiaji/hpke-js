export declare class XCryptoKey implements CryptoKey {
    readonly key: Uint8Array;
    readonly type: "public" | "private";
    readonly extractable: boolean;
    readonly algorithm: KeyAlgorithm;
    readonly usages: KeyUsage[];
    constructor(name: string, key: Uint8Array, type: "public" | "private");
}
