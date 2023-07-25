import type { KdfInterface } from "../interfaces/kdfInterface.js";
import { KdfId } from "../identifiers.js";
import { KdfAlgorithm } from "../algorithm.js";
export declare class Hkdf extends KdfAlgorithm implements KdfInterface {
    readonly id: KdfId;
    readonly hashSize: number;
    protected readonly algHash: HmacKeyGenParams;
    constructor();
    buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array;
    buildLabeledInfo(label: Uint8Array, info: Uint8Array, len: number): Uint8Array;
    extract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer>;
    expand(prk: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer>;
    extractAndExpand(salt: ArrayBuffer, ikm: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer>;
    labeledExtract(salt: ArrayBuffer, label: Uint8Array, ikm: Uint8Array): Promise<ArrayBuffer>;
    labeledExpand(prk: ArrayBuffer, label: Uint8Array, info: Uint8Array, len: number): Promise<ArrayBuffer>;
}
export declare class HkdfSha256 extends Hkdf implements KdfInterface {
    readonly id: KdfId;
    readonly hashSize: number;
    protected readonly algHash: HmacKeyGenParams;
}
export declare class HkdfSha384 extends Hkdf implements KdfInterface {
    readonly id: KdfId;
    readonly hashSize: number;
    protected readonly algHash: HmacKeyGenParams;
}
export declare class HkdfSha512 extends Hkdf implements KdfInterface {
    readonly id: KdfId;
    readonly hashSize: number;
    protected readonly algHash: HmacKeyGenParams;
}
