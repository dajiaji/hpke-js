import { EMPTY } from "./consts.js";
import { EncryptionContext } from "./encryptionContext.js";
import * as errors from "./errors.js";
export class RecipientContext extends EncryptionContext {
    async seal(data, aad = EMPTY) {
        if (this._r.baseNonce.length === 0) {
            throw new errors.SealError("Bidirectional encryption is not setup");
        }
        let ct;
        try {
            ct = await this._r.key.encrypt(this.computeNonce(this._r), data, aad);
        }
        catch (e) {
            throw new errors.SealError(e);
        }
        this.incrementSeq(this._r);
        return ct;
    }
    async open(data, aad = EMPTY) {
        let pt;
        try {
            pt = await this._f.key.decrypt(this.computeNonce(this._f), data, aad);
        }
        catch (e) {
            throw new errors.OpenError(e);
        }
        this.incrementSeq(this._f);
        return pt;
    }
}
