/**
 * The minimum inplementation of bignum to derive an EC key pair.
 */
export declare class Bignum {
    private _num;
    constructor(size: number);
    val(): Uint8Array;
    reset(): void;
    set(src: Uint8Array): void;
    isZero(): boolean;
    lessThan(v: Uint8Array): boolean;
}
