import { Ec } from "./kemPrimitives/ec.js";
import { X25519 } from "./kemPrimitives/x25519.js";
import { X448 } from "./kemPrimitives/x448.js";
import { Kem } from "./identifiers.js";
import { KdfCommon } from "./kdfCommon.js";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "./utils/misc.js";
import * as consts from "./consts.js";
import * as errors from "./errors.js";
export class KemContext extends KdfCommon {
    constructor(api, kem) {
        const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
        suiteId.set(i2Osp(kem, 2), 3);
        let algHash;
        switch (kem) {
            case Kem.DhkemP256HkdfSha256:
                algHash = { name: "HMAC", hash: "SHA-256", length: 256 };
                break;
            case Kem.DhkemP384HkdfSha384:
                algHash = { name: "HMAC", hash: "SHA-384", length: 384 };
                break;
            case Kem.DhkemP521HkdfSha512:
                algHash = { name: "HMAC", hash: "SHA-512", length: 512 };
                break;
            case Kem.DhkemX25519HkdfSha256:
                algHash = { name: "HMAC", hash: "SHA-256", length: 256 };
                break;
            default:
                // case Kem.DhkemX448HkdfSha512:
                algHash = { name: "HMAC", hash: "SHA-512", length: 512 };
                break;
        }
        super(api, suiteId, algHash);
        Object.defineProperty(this, "_prim", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_nSecret", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        switch (kem) {
            case Kem.DhkemP256HkdfSha256:
                this._prim = new Ec(kem, this, this._api);
                this._nSecret = 32;
                break;
            case Kem.DhkemP384HkdfSha384:
                this._prim = new Ec(kem, this, this._api);
                this._nSecret = 48;
                break;
            case Kem.DhkemP521HkdfSha512:
                this._prim = new Ec(kem, this, this._api);
                this._nSecret = 64;
                break;
            case Kem.DhkemX25519HkdfSha256:
                this._prim = new X25519(this);
                this._nSecret = 32;
                break;
            default:
                // case Kem.DhkemX448HkdfSha512:
                this._prim = new X448(this);
                this._nSecret = 64;
                break;
        }
    }
    async generateKeyPair() {
        return await this._prim.generateKeyPair();
    }
    async deriveKeyPair(ikm) {
        try {
            return await this._prim.deriveKeyPair(ikm);
        }
        catch (e) {
            throw new errors.DeriveKeyPairError(e);
        }
    }
    async importKey(format, key, isPublic) {
        try {
            return await this._prim.importKey(format, key, isPublic);
        }
        catch (e) {
            throw new errors.DeserializeError(e);
        }
    }
    async encap(params) {
        try {
            const ke = params.nonEphemeralKeyPair === undefined
                ? await this.generateKeyPair()
                : params.nonEphemeralKeyPair;
            const enc = await this._prim.serializePublicKey(ke.publicKey);
            const pkrm = await this._prim.serializePublicKey(params.recipientPublicKey);
            let dh;
            if (params.senderKey === undefined) {
                dh = new Uint8Array(await this._prim.dh(ke.privateKey, params.recipientPublicKey));
            }
            else {
                const sks = isCryptoKeyPair(params.senderKey)
                    ? params.senderKey.privateKey
                    : params.senderKey;
                const dh1 = new Uint8Array(await this._prim.dh(ke.privateKey, params.recipientPublicKey));
                const dh2 = new Uint8Array(await this._prim.dh(sks, params.recipientPublicKey));
                dh = concat(dh1, dh2);
            }
            let kemContext;
            if (params.senderKey === undefined) {
                kemContext = concat(new Uint8Array(enc), new Uint8Array(pkrm));
            }
            else {
                const pks = isCryptoKeyPair(params.senderKey)
                    ? params.senderKey.publicKey
                    : await this._prim.derivePublicKey(params.senderKey);
                const pksm = await this._prim.serializePublicKey(pks);
                kemContext = concat3(new Uint8Array(enc), new Uint8Array(pkrm), new Uint8Array(pksm));
            }
            const sharedSecret = await this.generateSharedSecret(dh, kemContext);
            return {
                enc: enc,
                sharedSecret: sharedSecret,
            };
        }
        catch (e) {
            throw new errors.EncapError(e);
        }
    }
    async decap(params) {
        let pke;
        try {
            pke = await this._prim.deserializePublicKey(params.enc);
        }
        catch (e) {
            throw new errors.DeserializeError(e);
        }
        try {
            const skr = isCryptoKeyPair(params.recipientKey)
                ? params.recipientKey.privateKey
                : params.recipientKey;
            const pkr = isCryptoKeyPair(params.recipientKey)
                ? params.recipientKey.publicKey
                : await this._prim.derivePublicKey(params.recipientKey);
            const pkrm = await this._prim.serializePublicKey(pkr);
            let dh;
            if (params.senderPublicKey === undefined) {
                dh = new Uint8Array(await this._prim.dh(skr, pke));
            }
            else {
                const dh1 = new Uint8Array(await this._prim.dh(skr, pke));
                const dh2 = new Uint8Array(await this._prim.dh(skr, params.senderPublicKey));
                dh = concat(dh1, dh2);
            }
            let kemContext;
            if (params.senderPublicKey === undefined) {
                kemContext = concat(new Uint8Array(params.enc), new Uint8Array(pkrm));
            }
            else {
                const pksm = await this._prim.serializePublicKey(params.senderPublicKey);
                kemContext = new Uint8Array(params.enc.byteLength + pkrm.byteLength + pksm.byteLength);
                kemContext.set(new Uint8Array(params.enc), 0);
                kemContext.set(new Uint8Array(pkrm), params.enc.byteLength);
                kemContext.set(new Uint8Array(pksm), params.enc.byteLength + pkrm.byteLength);
            }
            return await this.generateSharedSecret(dh, kemContext);
        }
        catch (e) {
            throw new errors.DecapError(e);
        }
    }
    async generateSharedSecret(dh, kemContext) {
        const labeledIkm = this.buildLabeledIkm(consts.LABEL_EAE_PRK, dh);
        const labeledInfo = this.buildLabeledInfo(consts.LABEL_SHARED_SECRET, kemContext, this._nSecret);
        return await this.extractAndExpand(consts.EMPTY, labeledIkm, labeledInfo, this._nSecret);
    }
}
