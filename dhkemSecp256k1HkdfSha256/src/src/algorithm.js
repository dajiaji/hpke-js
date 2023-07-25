import * as consts from "./consts.js";
export class AlgorithmBase {
    constructor() {
        Object.defineProperty(this, "_api", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: undefined
        });
    }
    checkInit() {
        if (typeof this._api === "undefined") {
            throw new Error("Not initialized. Call init()");
        }
    }
}
export class Algorithm extends AlgorithmBase {
    constructor() {
        super();
    }
    init(api) {
        this._api = api;
    }
}
export class KdfAlgorithm extends AlgorithmBase {
    constructor() {
        super();
        Object.defineProperty(this, "_suiteId", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: consts.EMPTY
        });
    }
    init(api, suiteId) {
        this._api = api;
        this._suiteId = suiteId;
    }
}
