import { KdfId } from "../identifiers.js";
/**
 * The KDF interface.
 */
export interface KdfInterface {
    /** The KDF identifier. */
    readonly id: KdfId;
    /** The output size of the extract() function in bytes (Nh). */
    readonly hashSize: number;
    buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array;
    buildLabeledInfo(label: Uint8Array, info: Uint8Array, len: number): Uint8Array;
    init(api: SubtleCrypto, suiteId: Uint8Array): void;
    extract(salt: ArrayBuffer, ikm: ArrayBuffer): Promise<ArrayBuffer>;
    expand(prk: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer>;
    extractAndExpand(salt: ArrayBuffer, ikm: ArrayBuffer, info: ArrayBuffer, len: number): Promise<ArrayBuffer>;
    labeledExtract(salt: ArrayBuffer, label: Uint8Array, ikm: Uint8Array): Promise<ArrayBuffer>;
    labeledExpand(prk: ArrayBuffer, label: Uint8Array, info: Uint8Array, len: number): Promise<ArrayBuffer>;
}
