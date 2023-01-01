import { generateKeyPair, scalarMultBase, sharedKey, } from "@stablelib/x25519";
import { XCryptoKey } from "../xCryptoKey.js";
import * as consts from "../consts.js";
const ALG_NAME = "X25519";
export class X25519 {
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
        if (format !== "raw") {
            throw new Error("Unsupported format");
        }
        return await this._importKey(key, isPublic);
    }
    async derivePublicKey(key) {
        return await this._derivePublicKey(key);
    }
    async generateKeyPair() {
        const kp = await generateKeyPair();
        return {
            publicKey: new XCryptoKey(ALG_NAME, kp.publicKey, "public"),
            privateKey: new XCryptoKey(ALG_NAME, kp.secretKey, "private"),
        };
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
            resolve(new XCryptoKey(ALG_NAME, scalarMultBase(k.key), "public"));
        });
    }
    _dh(sk, pk) {
        return new Promise((resolve, reject) => {
            try {
                resolve(sharedKey(sk.key, pk.key, true));
            }
            catch (e) {
                reject(e);
            }
        });
    }
}
