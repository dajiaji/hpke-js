import * as dntShim from "../../_dnt.shims.js";
/**
 * Checks whether the execution env is browser or not.
 */
export const isBrowser = () => typeof dntShim.dntGlobalThis !== "undefined";
/**
 * Checks whether the execution env is Cloudflare Workers or not.
 */
export const isCloudflareWorkers = () => typeof caches !== "undefined";
/**
 * Checks whether the execution env is Deno or not.
 */
export const isDeno = () => typeof Deno !== "undefined";
/**
 * Checks whetehr the type of input is CryptoKeyPair or not.
 */
export const isCryptoKeyPair = (x) => typeof x === "object" &&
    x !== null &&
    typeof x.privateKey === "object" &&
    typeof x.publicKey === "object";
/**
 * Converts integer to octet string. I2OSP implementation.
 */
export function i2Osp(n, w) {
    if (w <= 0) {
        throw new Error("i2Osp: too small size");
    }
    if (n >= 256 ** w) {
        throw new Error("i2Osp: too large integer");
    }
    const ret = new Uint8Array(w);
    for (let i = 0; i < w && n; i++) {
        ret[w - (i + 1)] = n % 256;
        n = n >> 8;
    }
    return ret;
}
/**
 * Executes XOR of two byte strings.
 */
export function xor(a, b) {
    if (a.byteLength !== b.byteLength) {
        throw new Error("xor: different length inputs");
    }
    const buf = new Uint8Array(a.byteLength);
    for (let i = 0; i < a.byteLength; i++) {
        buf[i] = a[i] ^ b[i];
    }
    return buf;
}
/**
 * Concatenates two Uint8Arrays.
 */
export function concat(a, b) {
    const ret = new Uint8Array(a.length + b.length);
    ret.set(a, 0);
    ret.set(b, a.length);
    return ret;
}
/**
 * Concatenates three Uint8Arrays.
 */
export function concat3(a, b, c) {
    const ret = new Uint8Array(a.length + b.length + c.length);
    ret.set(a, 0);
    ret.set(b, a.length);
    ret.set(c, a.length + b.length);
    return ret;
}
