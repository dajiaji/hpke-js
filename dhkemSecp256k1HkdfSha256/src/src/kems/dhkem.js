import { Algorithm } from "../algorithm.js";
import { Ec } from "./dhkemPrimitives/ec.js";
import { X25519 } from "./dhkemPrimitives/x25519.js";
import { X448 } from "./dhkemPrimitives/x448.js";
import { KemId } from "../identifiers.js";
import { HkdfSha256, HkdfSha384, HkdfSha512 } from "../kdfs/hkdf.js";
import { concat, concat3, i2Osp, isCryptoKeyPair } from "../utils/misc.js";
import * as consts from "../consts.js";
import * as errors from "../errors.js";
export class Dhkem extends Algorithm {
    constructor(prim, kdf) {
        super();
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KemId.DhkemP256HkdfSha256
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
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
        this._prim = prim;
        this._kdf = kdf;
    }
    init(api) {
        super.init(api);
        const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_KEM);
        suiteId.set(i2Osp(this.id, 2), 3);
        this._prim.init(api);
        this._kdf.init(api, suiteId);
        super.init(api);
    }
    async generateKeyPair() {
        try {
            return await this._prim.generateKeyPair();
        }
        catch (e) {
            throw new errors.NotSupportedError(e);
        }
    }
    async deriveKeyPair(ikm) {
        try {
            return await this._prim.deriveKeyPair(ikm);
        }
        catch (e) {
            throw new errors.DeriveKeyPairError(e);
        }
    }
    async serializePublicKey(key) {
        try {
            return await this._prim.serializePublicKey(key);
        }
        catch (e) {
            throw new errors.SerializeError(e);
        }
    }
    async deserializePublicKey(key) {
        try {
            return await this._prim.deserializePublicKey(key);
        }
        catch (e) {
            throw new errors.DeserializeError(e);
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
export class DhkemP256HkdfSha256 extends Dhkem {
    constructor() {
        const kdf = new HkdfSha256();
        const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
        super(prim, kdf);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KemId.DhkemP256HkdfSha256
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 65
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 65
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
    }
}
export class DhkemP384HkdfSha384 extends Dhkem {
    constructor() {
        const kdf = new HkdfSha384();
        const prim = new Ec(KemId.DhkemP384HkdfSha384, kdf);
        super(prim, kdf);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KemId.DhkemP384HkdfSha384
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 48
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 97
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 97
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 48
        });
    }
}
export class DhkemP521HkdfSha512 extends Dhkem {
    constructor() {
        const kdf = new HkdfSha512();
        const prim = new Ec(KemId.DhkemP521HkdfSha512, kdf);
        super(prim, kdf);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KemId.DhkemP521HkdfSha512
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 64
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 133
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 133
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 64
        });
    }
}
export class DhkemX25519HkdfSha256 extends Dhkem {
    constructor() {
        const kdf = new HkdfSha256();
        const prim = new X25519(kdf);
        super(prim, kdf);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KemId.DhkemX25519HkdfSha256
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 32
        });
    }
}
export class DhkemX448HkdfSha512 extends Dhkem {
    constructor() {
        const kdf = new HkdfSha512();
        const prim = new X448(kdf);
        super(prim, kdf);
        Object.defineProperty(this, "id", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: KemId.DhkemX448HkdfSha512
        });
        Object.defineProperty(this, "secretSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 64
        });
        Object.defineProperty(this, "encSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 56
        });
        Object.defineProperty(this, "publicKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 56
        });
        Object.defineProperty(this, "privateKeySize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 56
        });
    }
}
