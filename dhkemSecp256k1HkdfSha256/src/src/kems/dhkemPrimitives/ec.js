import { Algorithm } from "../../algorithm.js";
import { KemId } from "../../identifiers.js";
import { Bignum } from "../../utils/bignum.js";
import { i2Osp } from "../../utils/misc.js";
import * as consts from "../../consts.js";
const PKCS8_ALG_ID_P_256 = new Uint8Array([
    48,
    65,
    2,
    1,
    0,
    48,
    19,
    6,
    7,
    42,
    134,
    72,
    206,
    61,
    2,
    1,
    6,
    8,
    42,
    134,
    72,
    206,
    61,
    3,
    1,
    7,
    4,
    39,
    48,
    37,
    2,
    1,
    1,
    4,
    32,
]);
const PKCS8_ALG_ID_P_384 = new Uint8Array([
    48,
    78,
    2,
    1,
    0,
    48,
    16,
    6,
    7,
    42,
    134,
    72,
    206,
    61,
    2,
    1,
    6,
    5,
    43,
    129,
    4,
    0,
    34,
    4,
    55,
    48,
    53,
    2,
    1,
    1,
    4,
    48,
]);
const PKCS8_ALG_ID_P_521 = new Uint8Array([
    48,
    96,
    2,
    1,
    0,
    48,
    16,
    6,
    7,
    42,
    134,
    72,
    206,
    61,
    2,
    1,
    6,
    5,
    43,
    129,
    4,
    0,
    35,
    4,
    73,
    48,
    71,
    2,
    1,
    1,
    4,
    66,
]);
export class Ec extends Algorithm {
    constructor(kem, hkdf) {
        super();
        Object.defineProperty(this, "_hkdf", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_alg", {
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
        Object.defineProperty(this, "_nDh", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        // EC specific arguments for deriving key pair.
        Object.defineProperty(this, "_order", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_bitmask", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_pkcs8AlgId", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this._hkdf = hkdf;
        switch (kem) {
            case KemId.DhkemP256HkdfSha256:
                this._alg = { name: "ECDH", namedCurve: "P-256" };
                this._nPk = 65;
                this._nSk = 32;
                this._nDh = 32;
                this._order = consts.ORDER_P_256;
                this._bitmask = 0xFF;
                this._pkcs8AlgId = PKCS8_ALG_ID_P_256;
                break;
            case KemId.DhkemP384HkdfSha384:
                this._alg = { name: "ECDH", namedCurve: "P-384" };
                this._nPk = 97;
                this._nSk = 48;
                this._nDh = 48;
                this._order = consts.ORDER_P_384;
                this._bitmask = 0xFF;
                this._pkcs8AlgId = PKCS8_ALG_ID_P_384;
                break;
            default:
                // case KemId.DhkemP521HkdfSha512:
                this._alg = { name: "ECDH", namedCurve: "P-521" };
                this._nPk = 133;
                this._nSk = 66;
                this._nDh = 66;
                this._order = consts.ORDER_P_521;
                this._bitmask = 0x01;
                this._pkcs8AlgId = PKCS8_ALG_ID_P_521;
                break;
        }
    }
    async serializePublicKey(key) {
        this.checkInit();
        const ret = await this._api.exportKey("raw", key);
        // const ret = (await this._api.exportKey('spki', key)).slice(24);
        if (ret.byteLength !== this._nPk) {
            throw new Error("Invalid public key for the ciphersuite");
        }
        return ret;
    }
    async deserializePublicKey(key) {
        this.checkInit();
        if (key.byteLength !== this._nPk) {
            throw new Error("Invalid public key for the ciphersuite");
        }
        try {
            return await this._api.importKey("raw", key, this._alg, true, []);
        }
        catch (_e) {
            throw new Error("Invalid public key for the ciphersuite");
        }
    }
    async importKey(format, key, isPublic) {
        this.checkInit();
        if (format === "raw") {
            return await this._importRawKey(key, isPublic);
        }
        // jwk
        if (key instanceof ArrayBuffer) {
            throw new Error("Invalid jwk key format");
        }
        return await this._importJWK(key, isPublic);
    }
    async _importRawKey(key, isPublic) {
        if (isPublic && key.byteLength !== this._nPk) {
            throw new Error("Invalid public key for the ciphersuite");
        }
        if (!isPublic && key.byteLength !== this._nSk) {
            throw new Error("Invalid private key for the ciphersuite");
        }
        try {
            if (isPublic) {
                // return await this._api.importKey(format, key, this._alg, true, consts.KEM_USAGES);
                return await this._api.importKey("raw", key, this._alg, true, []);
            }
            const k = new Uint8Array(key);
            const pkcs8Key = new Uint8Array(this._pkcs8AlgId.length + k.length);
            pkcs8Key.set(this._pkcs8AlgId, 0);
            pkcs8Key.set(k, this._pkcs8AlgId.length);
            return await this._api.importKey("pkcs8", pkcs8Key, this._alg, true, consts.KEM_USAGES);
        }
        catch (_e) {
            throw new Error("Invalid key for the ciphersuite");
        }
    }
    async _importJWK(key, isPublic) {
        if (typeof key.crv === "undefined" || key.crv !== this._alg.namedCurve) {
            throw new Error(`Invalid crv: ${key.crv}`);
        }
        if (isPublic) {
            if (typeof key.d !== "undefined") {
                throw new Error("Invalid key: `d` should not be set");
            }
            return await this._api.importKey("jwk", key, this._alg, true, []);
        }
        if (typeof key.d === "undefined") {
            throw new Error("Invalid key: `d` not found");
        }
        return await this._api.importKey("jwk", key, this._alg, true, consts.KEM_USAGES);
    }
    async derivePublicKey(key) {
        this.checkInit();
        const jwk = await this._api.exportKey("jwk", key);
        delete jwk["d"];
        delete jwk["key_ops"];
        // return await this._api.importKey('jwk', jwk, this._alg, true, consts.KEM_USAGES);
        return await this._api.importKey("jwk", jwk, this._alg, true, []);
    }
    async generateKeyPair() {
        this.checkInit();
        return await this._api.generateKey(this._alg, true, consts.KEM_USAGES);
    }
    async deriveKeyPair(ikm) {
        this.checkInit();
        const dkpPrk = await this._hkdf.labeledExtract(consts.EMPTY, consts.LABEL_DKP_PRK, new Uint8Array(ikm));
        const bn = new Bignum(this._nSk);
        for (let counter = 0; bn.isZero() || !bn.lessThan(this._order); counter++) {
            if (counter > 255) {
                throw new Error("Faild to derive a key pair");
            }
            const bytes = new Uint8Array(await this._hkdf.labeledExpand(dkpPrk, consts.LABEL_CANDIDATE, i2Osp(counter, 1), this._nSk));
            bytes[0] = bytes[0] & this._bitmask;
            bn.set(bytes);
        }
        const pkcs8Key = new Uint8Array(this._pkcs8AlgId.length + bn.val().length);
        pkcs8Key.set(this._pkcs8AlgId, 0);
        pkcs8Key.set(bn.val(), this._pkcs8AlgId.length);
        const sk = await this._api.importKey("pkcs8", pkcs8Key, this._alg, true, consts.KEM_USAGES);
        bn.reset();
        return {
            privateKey: sk,
            publicKey: await this.derivePublicKey(sk),
        };
    }
    async dh(sk, pk) {
        this.checkInit();
        const bits = await this._api.deriveBits({
            name: "ECDH",
            public: pk,
        }, sk, this._nDh * 8);
        return bits;
    }
}
