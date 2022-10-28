import { SHA256 } from "../sha256/mod.ts";
import { SHA512 } from "../sha512/mod.ts";

const SHA256_REGEX: RegExp = /^\s*sha-?256\s*$/i;
const SHA512_REGEX: RegExp = /^\s*sha-?512\s*$/i;

/** An interface representation of a hash algorithm implementation. */
export interface Hash {
  hashSize: number;
  init(): Hash;
  update(msg: Uint8Array): Hash;
  digest(): Uint8Array;
}

/** A class representation of the HMAC algorithm. */
export class HMAC {
  readonly hashSize: number;
  readonly B: number;
  readonly iPad: number;
  readonly oPad: number;

  private iKeyPad!: Uint8Array;
  private oKeyPad!: Uint8Array;
  private hasher: Hash;

  /** Creates a new HMAC instance. */
  constructor(hasher: Hash, key?: Uint8Array) {
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
  init(key: Uint8Array): HMAC {
    if (!key) {
      key = new Uint8Array(0);
    }

    // process the key
    let _key: Uint8Array = new Uint8Array(key);

    if (_key.length > this.B) {
      // keys longer than blocksize are shortened
      this.hasher.init();
      _key = this.hasher.update(key).digest() as Uint8Array;
    }

    // zeropadr
    if (_key.byteLength < this.B) {
      const tmp: Uint8Array = new Uint8Array(this.B);
      tmp.set(_key, 0);
      _key = tmp;
    }

    // setup the key pads
    this.iKeyPad = new Uint8Array(this.B);
    this.oKeyPad = new Uint8Array(this.B);

    for (let i: number = 0; i < this.B; ++i) {
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
  update(
    msg: Uint8Array = new Uint8Array(0)
  ): HMAC {
    this.hasher.update(msg);

    return this;
  }

  /** Finalize the HMAC with additional message data. */
  digest(): Uint8Array {
    const sum1: Uint8Array = this.hasher.digest() as Uint8Array; // get sum 1

    this.hasher.init();

    return this.hasher
      .update(this.oKeyPad)
      .update(sum1)
      .digest();
  }
}

/** Returns a HMAC of the given msg and key using the indicated hash. */
export function hmac(
  hash: string,
  key: Uint8Array,
  msg?: Uint8Array,
): string | Uint8Array {
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
  throw new TypeError(
    `Unsupported hash ${hash}. Must be one of SHA(1|256|512).`
  );
}
