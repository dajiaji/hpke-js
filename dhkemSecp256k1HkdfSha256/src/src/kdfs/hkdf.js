import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { sha384, sha512 } from "@noble/hashes/sha512";
import { KdfId } from "../identifiers.js";
import { KdfAlgorithm } from "../algorithm.js";
import * as consts from "../consts.js";
export class Hkdf extends KdfAlgorithm {
    constructor() {
        super();
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KdfId.HkdfSha256
        });
        Object.defineProperty(this, "hashSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "algHash", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: {
                name: "HMAC",
                hash: "SHA-256",
                length: 256,
            }
        });
    }
    buildLabeledIkm(label, ikm) {
        const ret = new Uint8Array(7 + this._suiteId.byteLength + label.byteLength + ikm.byteLength);
        ret.set(consts.HPKE_VERSION, 0);
        ret.set(this._suiteId, 7);
        ret.set(label, 7 + this._suiteId.byteLength);
        ret.set(ikm, 7 + this._suiteId.byteLength + label.byteLength);
        return ret;
    }
    buildLabeledInfo(label, info, len) {
        const ret = new Uint8Array(9 + this._suiteId.byteLength + label.byteLength + info.byteLength);
        ret.set(new Uint8Array([0, len]), 0);
        ret.set(consts.HPKE_VERSION, 2);
        ret.set(this._suiteId, 9);
        ret.set(label, 9 + this._suiteId.byteLength);
        ret.set(info, 9 + this._suiteId.byteLength + label.byteLength);
        return ret;
    }
    async extract(salt, ikm) {
        this.checkInit();
        if (salt.byteLength === 0) {
            salt = new ArrayBuffer(this.hashSize);
        }
        if (salt.byteLength !== this.hashSize) {
            // Web Cryptography API supports only Nh(hashSize) length key.
            // In this case, fallback to the upper-layer hmac library.
            switch (this.algHash.hash) {
                case "SHA-256":
                    return hmac(sha256, new Uint8Array(salt), new Uint8Array(ikm));
                case "SHA-384":
                    return hmac(sha384, new Uint8Array(salt), new Uint8Array(ikm));
                default:
                    // case "SHA-512":
                    return hmac(sha512, new Uint8Array(salt), new Uint8Array(ikm));
            }
        }
        const key = await this._api.importKey("raw", salt, this.algHash, false, [
            "sign",
        ]);
        return await this._api.sign("HMAC", key, ikm);
    }
    async expand(prk, info, len) {
        this.checkInit();
        const key = await this._api.importKey("raw", prk, this.algHash, false, [
            "sign",
        ]);
        const okm = new ArrayBuffer(len);
        const p = new Uint8Array(okm);
        let prev = consts.EMPTY;
        const mid = new Uint8Array(info);
        const tail = new Uint8Array(1);
        if (len > 255 * this.hashSize) {
            throw new Error("Entropy limit reached");
        }
        const tmp = new Uint8Array(this.hashSize + mid.length + 1);
        for (let i = 1, cur = 0; cur < p.length; i++) {
            tail[0] = i;
            tmp.set(prev, 0);
            tmp.set(mid, prev.length);
            tmp.set(tail, prev.length + mid.length);
            prev = new Uint8Array(await this._api.sign("HMAC", key, tmp.slice(0, prev.length + mid.length + 1)));
            if (p.length - cur >= prev.length) {
                p.set(prev, cur);
                cur += prev.length;
            }
            else {
                p.set(prev.slice(0, p.length - cur), cur);
                cur += p.length - cur;
            }
        }
        return okm;
    }
    async extractAndExpand(salt, ikm, info, len) {
        this.checkInit();
        const baseKey = await this._api.importKey("raw", ikm, "HKDF", false, consts.KEM_USAGES);
        return await this._api.deriveBits({
            name: "HKDF",
            hash: this.algHash.hash,
            salt: salt,
            info: info,
        }, baseKey, len * 8);
    }
    async labeledExtract(salt, label, ikm) {
        return await this.extract(salt, this.buildLabeledIkm(label, ikm));
    }
    async labeledExpand(prk, label, info, len) {
        return await this.expand(prk, this.buildLabeledInfo(label, info, len), len);
    }
}
export class HkdfSha256 extends Hkdf {
    constructor() {
        super(...arguments);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KdfId.HkdfSha256
        });
        Object.defineProperty(this, "hashSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
        Object.defineProperty(this, "algHash", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: {
                name: "HMAC",
                hash: "SHA-256",
                length: 256,
            }
        });
    }
}
export class HkdfSha384 extends Hkdf {
    constructor() {
        super(...arguments);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KdfId.HkdfSha384
        });
        Object.defineProperty(this, "hashSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 48
        });
        Object.defineProperty(this, "algHash", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: {
                name: "HMAC",
                hash: "SHA-384",
                length: 384,
            }
        });
    }
}
export class HkdfSha512 extends Hkdf {
    constructor() {
        super(...arguments);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KdfId.HkdfSha512
        });
        Object.defineProperty(this, "hashSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 64
        });
        Object.defineProperty(this, "algHash", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: {
                name: "HMAC",
                hash: "SHA-512",
                length: 512,
            }
        });
    }
}
