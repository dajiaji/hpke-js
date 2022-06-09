import { ChaCha20Poly1305 } from "../bundles/chacha20poly1305/chacha20poly1305.js";
export class Chacha20Poly1305Key {
    constructor(key) {
        Object.defineProperty(this, "_key", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this._key = new ChaCha20Poly1305(new Uint8Array(key));
    }
    async encrypt(iv, data, aad) {
        return await this._encrypt(iv, data, aad);
    }
    async decrypt(iv, data, aad) {
        return await this._decrypt(iv, data, aad);
    }
    _encrypt(iv, data, aad) {
        return new Promise((resolve) => {
            const ret = this._key.seal(new Uint8Array(iv), new Uint8Array(data), new Uint8Array(aad));
            resolve(ret.buffer);
        });
    }
    _decrypt(iv, data, aad) {
        return new Promise((resolve, reject) => {
            const ret = this._key.open(new Uint8Array(iv), new Uint8Array(data), new Uint8Array(aad));
            if (ret instanceof Uint8Array) {
                resolve(ret.buffer);
            }
            else {
                reject(new Error("failed to open."));
            }
        });
    }
}
