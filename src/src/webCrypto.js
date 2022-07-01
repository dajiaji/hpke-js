import { isBrowser, isCloudflareWorkers } from "./utils/misc.js";
import * as errors from "./errors.js";
export class WebCrypto {
    constructor(api) {
        Object.defineProperty(this, "_api", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this._api = api;
    }
}
export async function loadCrypto() {
    if (isBrowser() || isCloudflareWorkers()) {
        if (globalThis.crypto !== undefined) {
            return globalThis.crypto;
        }
        // jsdom
    }
    try {
        const { webcrypto } = await import("crypto"); // node:crypto
        return webcrypto;
    }
    catch (_e) {
        throw new errors.NotSupportedError("Web Cryptograph API not supported");
    }
}
export async function loadSubtleCrypto() {
    if (isBrowser() || isCloudflareWorkers()) {
        if (globalThis.crypto !== undefined) {
            return globalThis.crypto.subtle;
        }
        // jsdom
    }
    try {
        const { webcrypto } = await import("crypto"); // node:crypto
        return webcrypto.subtle;
    }
    catch (_e) {
        throw new errors.NotSupportedError("Web Cryptograph API not supported");
    }
}
