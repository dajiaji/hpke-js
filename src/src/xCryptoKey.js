import * as consts from "./consts.js";
export class XCryptoKey {
    constructor(name, key, type) {
        Object.defineProperty(this, "key", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "type", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "extractable", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: true
        });
        Object.defineProperty(this, "algorithm", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "usages", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: consts.KEM_USAGES
        });
        this.key = key;
        this.type = type;
        this.algorithm = { name: name };
    }
}
