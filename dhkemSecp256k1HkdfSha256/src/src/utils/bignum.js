/**
 * The minimum inplementation of bignum to derive an EC key pair.
 */
export class Bignum {
    constructor(size) {
        Object.defineProperty(this, "_num", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this._num = new Uint8Array(size);
    }
    val() {
        return this._num;
    }
    reset() {
        this._num.fill(0);
    }
    set(src) {
        if (src.length !== this._num.length) {
            throw new Error("Bignum.set: invalid argument");
        }
        this._num.set(src);
    }
    isZero() {
        for (let i = 0; i < this._num.length; i++) {
            if (this._num[i] !== 0) {
                return false;
            }
        }
        return true;
    }
    lessThan(v) {
        if (v.length !== this._num.length) {
            throw new Error("Bignum.lessThan: invalid argument");
        }
        for (let i = 0; i < this._num.length; i++) {
            if (this._num[i] < v[i]) {
                return true;
            }
            if (this._num[i] > v[i]) {
                return false;
            }
        }
        return false;
    }
}
