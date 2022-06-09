import * as consts from "../consts.js";
export class AesGcmKey {
    constructor(key, api) {
        Object.defineProperty(this, "_rawKey", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_key", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: undefined
        });
        Object.defineProperty(this, "_api", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this._rawKey = key;
        this._api = api;
    }
    async encrypt(iv, data, aad) {
        if (this._key === undefined) {
            this._key = await this.importKey(this._rawKey);
            (new Uint8Array(this._rawKey)).fill(0);
        }
        const alg = {
            name: "AES-GCM",
            iv: iv,
            additionalData: aad,
        };
        const ct = await this._api.encrypt(alg, this._key, data);
        return ct;
    }
    async decrypt(iv, data, aad) {
        if (this._key === undefined) {
            this._key = await this.importKey(this._rawKey);
            (new Uint8Array(this._rawKey)).fill(0);
        }
        const alg = {
            name: "AES-GCM",
            iv: iv,
            additionalData: aad,
        };
        const pt = await this._api.decrypt(alg, this._key, data);
        return pt;
    }
    async importKey(key) {
        return await this._api.importKey("raw", key, { name: "AES-GCM" }, true, consts.AEAD_USAGES);
    }
}
