import { getPublicKey, getSharedSecret } from "../bundles/x448-js/index.js";
import { loadCrypto } from "../webCrypto.js";
import { XCryptoKey } from "../xCryptoKey.js";
import * as consts from "../consts.js";
const ALG_NAME = "X448";
export class X448 {
    constructor(hkdf) {
        Object.defineProperty(this, "_hkdf", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_nPk", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_nSk", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this._hkdf = hkdf;
        this._nPk = 56;
        this._nSk = 56;
    }
    async serializePublicKey(key) {
        return await this._serializePublicKey(key);
    }
    async deserializePublicKey(key) {
        return await this._deserializePublicKey(key);
    }
    async importKey(format, key, isPublic) {
        if (format !== "raw") {
            throw new Error("Unsupported format");
        }
        return await this._importKey(key, isPublic);
    }
    async derivePublicKey(key) {
        return await this._derivePublicKey(key);
    }
    async generateKeyPair() {
        const sk = new Uint8Array(56);
        const cryptoApi = await loadCrypto();
        cryptoApi.getRandomValues(sk);
        return await this.deriveKeyPair(sk);
    }
    async deriveKeyPair(ikm) {
        const dkpPrk = await this._hkdf.labeledExtract(consts.EMPTY, consts.LABEL_DKP_PRK, new Uint8Array(ikm));
        const rawSk = await this._hkdf.labeledExpand(dkpPrk, consts.LABEL_SK, consts.EMPTY, this._nSk);
        const sk = new XCryptoKey(ALG_NAME, new Uint8Array(rawSk), "private");
        return {
            privateKey: sk,
            publicKey: await this.derivePublicKey(sk),
        };
    }
    async dh(sk, pk) {
        return await this._dh(sk, pk);
    }
    _serializePublicKey(k) {
        return new Promise((resolve) => {
            resolve(k.key.buffer);
        });
    }
    _deserializePublicKey(k) {
        return new Promise((resolve, reject) => {
            if (k.byteLength !== this._nPk) {
                reject(new Error("Invalid public key for the ciphersuite"));
            }
            else {
                resolve(new XCryptoKey(ALG_NAME, new Uint8Array(k), "public"));
            }
        });
    }
    _importKey(key, isPublic) {
        return new Promise((resolve, reject) => {
            if (isPublic && key.byteLength !== this._nPk) {
                reject(new Error("Invalid public key for the ciphersuite"));
            }
            if (!isPublic && key.byteLength !== this._nSk) {
                reject(new Error("Invalid private key for the ciphersuite"));
            }
            resolve(new XCryptoKey(ALG_NAME, new Uint8Array(key), isPublic ? "public" : "private"));
        });
    }
    _derivePublicKey(k) {
        return new Promise((resolve) => {
            resolve(new XCryptoKey(ALG_NAME, Uint8Array.from(getPublicKey(k.key)), "public"));
        });
    }
    _dh(sk, pk) {
        return new Promise((resolve, reject) => {
            try {
                resolve(Uint8Array.from(getSharedSecret(sk.key, pk.key)));
            }
            catch (e) {
                reject(e);
            }
        });
    }
}
