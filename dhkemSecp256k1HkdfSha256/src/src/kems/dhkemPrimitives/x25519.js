import { ed25519, x25519 } from "@noble/curves/ed25519";
import { Algorithm } from "../../algorithm.js";
import { XCryptoKey } from "../../xCryptoKey.js";
import * as consts from "../../consts.js";
import { base64UrlToBytes } from "../../utils/misc.js";
const ALG_NAME = "X25519";
export class X25519 extends Algorithm {
    constructor(hkdf) {
        super();
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
        this._nPk = 32;
        this._nSk = 32;
    }
    async serializePublicKey(key) {
        return await this._serializePublicKey(key);
    }
    async deserializePublicKey(key) {
        return await this._deserializePublicKey(key);
    }
    async importKey(format, key, isPublic) {
        if (format === "raw") {
            return await this._importRawKey(key, isPublic);
        }
        // jwk
        if (key instanceof ArrayBuffer) {
            throw new Error("Invalid jwk key format");
        }
        return await this._importJWK(key, isPublic);
    }
    async derivePublicKey(key) {
        return await this._derivePublicKey(key);
    }
    async generateKeyPair() {
        const rawSk = ed25519.utils.randomPrivateKey();
        const sk = new XCryptoKey(ALG_NAME, rawSk, "private");
        const pk = await this.derivePublicKey(sk);
        return { publicKey: pk, privateKey: sk };
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
    _importRawKey(key, isPublic) {
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
    _importJWK(key, isPublic) {
        return new Promise((resolve, reject) => {
            if (typeof key.kty === "undefined" || key.kty !== "OKP") {
                reject(new Error(`Invalid kty: ${key.kty}`));
            }
            if (typeof key.crv === "undefined" || key.crv !== "X25519") {
                reject(new Error(`Invalid crv: ${key.crv}`));
            }
            if (isPublic) {
                if (typeof key.d !== "undefined") {
                    reject(new Error("Invalid key: `d` should not be set"));
                }
                if (typeof key.x === "undefined") {
                    reject(new Error("Invalid key: `x` not found"));
                }
                resolve(new XCryptoKey(ALG_NAME, base64UrlToBytes(key.x), "public"));
            }
            else {
                if (typeof key.d !== "string") {
                    reject(new Error("Invalid key: `d` not found"));
                }
                resolve(new XCryptoKey(ALG_NAME, base64UrlToBytes(key.d), "private"));
            }
        });
    }
    _derivePublicKey(k) {
        return new Promise((resolve) => {
            const pk = x25519.getPublicKey(k.key);
            resolve(new XCryptoKey(ALG_NAME, pk, "public"));
        });
    }
    _dh(sk, pk) {
        return new Promise((resolve, reject) => {
            try {
                resolve(x25519.getSharedSecret(sk.key, pk.key).buffer);
            }
            catch (e) {
                reject(e);
            }
        });
    }
}
