export declare class AlgorithmBase {
    protected _api: SubtleCrypto | undefined;
    constructor();
    protected checkInit(): void;
}
export declare class Algorithm extends AlgorithmBase {
    constructor();
    init(api: SubtleCrypto): void;
}
export declare class KdfAlgorithm extends AlgorithmBase {
    protected _suiteId: Uint8Array;
    constructor();
    init(api: SubtleCrypto, suiteId: Uint8Array): void;
}
