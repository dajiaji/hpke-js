import { SHA256 } from "../sha256/mod.js";
import { SHA512 } from "../sha512/mod.js";
const SHA256_REGEX = /^\s*sha-?256\s*$/i;
const SHA512_REGEX = /^\s*sha-?512\s*$/i;
/** A class representation of the HMAC algorithm. */
export class HMAC {
    /** Creates a new HMAC instance. */
    constructor(hasher, key) {
        Object.defineProperty(this, "hashSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "B", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "iPad", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "oPad", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "iKeyPad", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "oKeyPad", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "hasher", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.hashSize = hasher.hashSize;
        this.hasher = hasher;
        this.B = this.hashSize <= 32 ? 64 : 128; // according to RFC4868
        this.iPad = 0x36;
        this.oPad = 0x5c;
        if (key) {
            this.init(key);
        }
    }
    /** Initializes an HMAC instance. */
    init(key) {
        if (!key) {
            key = new Uint8Array(0);
        }
        // process the key
        let _key = new Uint8Array(key);
        if (_key.length > this.B) {
            // keys longer than blocksize are shortened
            this.hasher.init();
            _key = this.hasher.update(key).digest();
        }
        // zeropadr
        if (_key.byteLength < this.B) {
            const tmp = new Uint8Array(this.B);
            tmp.set(_key, 0);
            _key = tmp;
        }
        // setup the key pads
        this.iKeyPad = new Uint8Array(this.B);
        this.oKeyPad = new Uint8Array(this.B);
        for (let i = 0; i < this.B; ++i) {
            this.iKeyPad[i] = this.iPad ^ _key[i];
            this.oKeyPad[i] = this.oPad ^ _key[i];
        }
        // blackout key
        _key.fill(0);
        // initial hash
        this.hasher.init();
        this.hasher.update(this.iKeyPad);
        return this;
    }
    /** Update the HMAC with additional message data. */
    update(msg = new Uint8Array(0)) {
        this.hasher.update(msg);
        return this;
    }
    /** Finalize the HMAC with additional message data. */
    digest() {
        const sum1 = this.hasher.digest(); // get sum 1
        this.hasher.init();
        return this.hasher
            .update(this.oKeyPad)
            .update(sum1)
            .digest();
    }
}
/** Returns a HMAC of the given msg and key using the indicated hash. */
export function hmac(hash, key, msg) {
    if (SHA256_REGEX.test(hash)) {
        return new HMAC(new SHA256())
            .init(key)
            .update(msg)
            .digest();
    }
    if (SHA512_REGEX.test(hash)) {
        return new HMAC(new SHA512())
            .init(key)
            .update(msg)
            .digest();
    }
    throw new TypeError(`Unsupported hash ${hash}. Must be one of SHA(1|256|512).`);
}
