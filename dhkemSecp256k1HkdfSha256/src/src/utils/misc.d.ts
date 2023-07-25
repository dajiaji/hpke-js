/**
 * Checks whether the execution env is browser or not.
 */
export declare const isBrowser: () => boolean;
/**
 * Checks whether the execution env is Cloudflare Workers or not.
 */
export declare const isCloudflareWorkers: () => boolean;
/**
 * Checks whether the execution env is Deno or not.
 */
export declare const isDeno: () => boolean;
/**
 * Checks whetehr the type of input is CryptoKeyPair or not.
 */
export declare const isCryptoKeyPair: (x: unknown) => x is CryptoKeyPair;
/**
 * Converts integer to octet string. I2OSP implementation.
 */
export declare function i2Osp(n: number, w: number): Uint8Array;
/**
 * Executes XOR of two byte strings.
 */
export declare function xor(a: Uint8Array, b: Uint8Array): Uint8Array;
/**
 * Concatenates two Uint8Arrays.
 */
export declare function concat(a: Uint8Array, b: Uint8Array): Uint8Array;
/**
 * Concatenates three Uint8Arrays.
 */
export declare function concat3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array;
/**
 * Converts hex string to bytes.
 */
export declare function hexToBytes(v: string): Uint8Array;
/**
 * Converts bytes to hex string.
 */
export declare function bytesToHex(v: Uint8Array): string;
/**
 * Decodes Base64Url-encoded data.
 */
export declare function base64UrlToBytes(v: string): Uint8Array;
