import { Ec } from "./kemPrimitives/ec.js";
import { X25519 } from "./kemPrimitives/x25519.js";
import { X448 } from "./kemPrimitives/x448.js";
import { Kdf, Kem } from "./identifiers.js";
import { KdfContext } from "./kdfContext.js";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "./utils/misc.js";
import { WebCrypto } from "./webCrypto.js";
import * as consts from "./consts.js";
import * as errors from "./errors.js";
export class KemContext extends WebCrypto {
    constructor(api, kem) {
        super(api);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_prim", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "_kdf", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.id = kem;
        let kdfId = Kdf.HkdfSha256;
        switch (kem) {
            case Kem.DhkemP256HkdfSha256:
                kdfId = Kdf.HkdfSha256;
                break;
            case Kem.DhkemP384HkdfSha384:
                kdfId = Kdf.HkdfSha384;
                break;
            case Kem.DhkemP521HkdfSha512:
                kdfId = Kdf.HkdfSha512;
                break;
            case Kem.DhkemX25519HkdfSha256:
                kdfId = Kdf.HkdfSha256;
                break;
            default:
                kdfId = Kdf.HkdfSha512;
                // case Kem.DhkemX448HkdfSha512:
                break;
        }
        const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
        suiteId.set(i2Osp(kem, 2), 3);
        this._kdf = new KdfContext(this._api, kdfId, suiteId);
        switch (kem) {
            case Kem.DhkemP256HkdfSha256:
                this._prim = new Ec(kem, this._kdf, this._api);
                this.secretSize = 32;
                this.encSize = 65;
                this.publicKeySize = 65;
                this.privateKeySize = 32;
                break;
            case Kem.DhkemP384HkdfSha384:
                this._prim = new Ec(kem, this._kdf, this._api);
                this.secretSize = 48;
                this.encSize = 97;
                this.publicKeySize = 97;
                this.privateKeySize = 48;
                break;
            case Kem.DhkemP521HkdfSha512:
                this._prim = new Ec(kem, this._kdf, this._api);
                this.secretSize = 64;
                this.encSize = 133;
                this.publicKeySize = 133;
                this.privateKeySize = 66;
                break;
            case Kem.DhkemX25519HkdfSha256:
                this._prim = new X25519(this._kdf);
                this.secretSize = 32;
                this.encSize = 32;
                this.publicKeySize = 32;
                this.privateKeySize = 32;
                break;
            default:
                // case Kem.DhkemX448HkdfSha512:
                this._prim = new X448(this._kdf);
                this.secretSize = 64;
                this.encSize = 56;
                this.publicKeySize = 56;
                this.privateKeySize = 56;
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
        const labeledIkm = this._kdf.buildLabeledIkm(consts.LABEL_EAE_PRK, dh);
        const labeledInfo = this._kdf.buildLabeledInfo(consts.LABEL_SHARED_SECRET, kemContext, this.secretSize);
        return await this._kdf.extractAndExpand(consts.EMPTY, labeledIkm, labeledInfo, this.secretSize);
    }
}
