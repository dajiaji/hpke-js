import { EMPTY } from "./consts.js";
import { EncryptionContext } from "./encryptionContext.js";
import * as errors from "./errors.js";
export class SenderContext extends EncryptionContext {
    constructor(api, kdf, params, enc) {
        super(api, kdf, params);
        Object.defineProperty(this, "enc", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.enc = enc;
    }
    async seal(data, aad = EMPTY) {
        let ct;
        try {
            ct = await this._f.key.encrypt(this.computeNonce(this._f), data, aad);
        }
        catch (e) {
            throw new errors.SealError(e);
        }
        this.incrementSeq(this._f);
        return ct;
    }
    async open(data, aad = EMPTY) {
        if (this._r.baseNonce.length === 0) {
            throw new errors.OpenError("Bidirectional encryption is not setup");
        }
        let pt;
        try {
            pt = await this._r.key.decrypt(this.computeNonce(this._r), data, aad);
        }
        catch (e) {
            throw new errors.OpenError(e);
        }
        this.incrementSeq(this._r);
        return pt;
    }
}
