import { WebCrypto } from "./webCrypto.js";
import * as consts from "./consts.js";
import * as errors from "./errors.js";
export class ExporterContext extends WebCrypto {
    constructor(api, kdf, exporterSecret) {
        super(api);
        Object.defineProperty(this, "exporterSecret", {
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
        this._kdf = kdf;
        this.exporterSecret = exporterSecret;
    }
    async seal(_data, _aad) {
        return await this._emitError1();
    }
    async open(_data, _aad) {
        return await this._emitError1();
    }
    async setupBidirectional(_keySeed, _nonceSeed) {
        return await this._emitError2();
    }
    async export(exporterContext, len) {
        if (exporterContext.byteLength > consts.INPUT_LENGTH_LIMIT) {
            throw new errors.InvalidParamError("Too long exporter context");
        }
        try {
            return await this._kdf.labeledExpand(this.exporterSecret, consts.LABEL_SEC, new Uint8Array(exporterContext), len);
        }
        catch (e) {
            throw new errors.ExportError(e);
        }
    }
    _emitError1() {
        return new Promise((_resolve, reject) => {
            reject(new errors.NotSupportedError("Not available on export-only mode"));
        });
    }
    _emitError2() {
        return new Promise((_resolve, reject) => {
            reject(new errors.NotSupportedError("Not available on export-only mode"));
        });
    }
}
export class RecipientExporterContext extends ExporterContext {
}
export class SenderExporterContext extends ExporterContext {
    constructor(api, kdf, exporterSecret, enc) {
        super(api, kdf, exporterSecret);
        Object.defineProperty(this, "enc", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.enc = enc;
        return;
    }
}
