import type { KdfInterface } from "../interfaces/kdfInterface.ts";

import { EMPTY } from "../consts.ts";
import { InvalidParamError } from "../errors.ts";
import { KdfId } from "../identifiers.ts";
import { NativeAlgorithm } from "../algorithm.ts";

// b"HPKE-v1"
const HPKE_VERSION = /* @__PURE__ */ new Uint8Array([
  72,
  80,
  75,
  69,
  45,
  118,
  49,
]);

export function toUint8Array(
  input: ArrayBufferLike | ArrayBufferView,
): Uint8Array {
  return new Uint8Array(toArrayBuffer(input));
}

export function toArrayBuffer(
  input: ArrayBufferLike | ArrayBufferView,
): ArrayBuffer {
  if (input instanceof ArrayBuffer) {
    return input;
  }
  if (ArrayBuffer.isView(input)) {
    return new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
      .slice().buffer;
  }
  return new Uint8Array(input).slice().buffer;
}

export class HkdfNative extends NativeAlgorithm implements KdfInterface {
  public readonly id: KdfId = KdfId.HkdfSha256;
  public readonly hashSize: number = 0;
  protected _suiteId: Uint8Array = EMPTY;
  protected readonly algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-256",
    length: 256,
  };

  constructor() {
    super();
  }

  public init(suiteId: Uint8Array): void {
    this._suiteId = suiteId;
  }

  public buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array {
    this._checkInit();
    const ret = new Uint8Array(
      7 + this._suiteId.byteLength + label.byteLength + ikm.byteLength,
    );
    ret.set(HPKE_VERSION, 0);
    ret.set(this._suiteId, 7);
    ret.set(label, 7 + this._suiteId.byteLength);
    ret.set(ikm, 7 + this._suiteId.byteLength + label.byteLength);
    return ret;
  }

  public buildLabeledInfo(
    label: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Uint8Array {
    this._checkInit();
    const ret = new Uint8Array(
      9 + this._suiteId.byteLength + label.byteLength + info.byteLength,
    );
    ret.set(new Uint8Array([0, len]), 0);
    ret.set(HPKE_VERSION, 2);
    ret.set(this._suiteId, 9);
    ret.set(label, 9 + this._suiteId.byteLength);
    ret.set(info, 9 + this._suiteId.byteLength + label.byteLength);
    return ret;
  }

  public async extract(
    salt: ArrayBufferLike | ArrayBufferView,
    ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    await this._setup();
    const saltBuf = salt.byteLength === 0
      ? new ArrayBuffer(this.hashSize)
      : toArrayBuffer(salt);
    if (saltBuf.byteLength !== this.hashSize) {
      throw new InvalidParamError(
        "The salt length must be the same as the hashSize",
      );
    }
    const ikmBuf = toArrayBuffer(ikm);
    const key = await (this._api as SubtleCrypto).importKey(
      "raw",
      saltBuf,
      this.algHash,
      false,
      [
        "sign",
      ],
    );
    return await (this._api as SubtleCrypto).sign("HMAC", key, ikmBuf);
  }

  public async expand(
    prk: ArrayBufferLike | ArrayBufferView,
    info: ArrayBufferLike | ArrayBufferView,
    len: number,
  ): Promise<ArrayBuffer> {
    await this._setup();
    const prkBuf = toArrayBuffer(prk);
    const key = await (this._api as SubtleCrypto).importKey(
      "raw",
      prkBuf,
      this.algHash,
      false,
      [
        "sign",
      ],
    );

    const okm = new ArrayBuffer(len);
    const okmBytes = new Uint8Array(okm);
    let prev = EMPTY;
    const mid = toUint8Array(info);
    const tail = new Uint8Array(1);

    if (len > 255 * this.hashSize) {
      throw new Error("Entropy limit reached");
    }

    const tmp = new Uint8Array(this.hashSize + mid.length + 1);
    for (let i = 1, cur = 0; cur < okmBytes.length; i++) {
      tail[0] = i;
      tmp.set(prev, 0);
      tmp.set(mid, prev.length);
      tmp.set(tail, prev.length + mid.length);
      prev = new Uint8Array(
        await (this._api as SubtleCrypto).sign(
          "HMAC",
          key,
          tmp.slice(0, prev.length + mid.length + 1),
        ),
      );
      if (okmBytes.length - cur >= prev.length) {
        okmBytes.set(prev, cur);
        cur += prev.length;
      } else {
        okmBytes.set(prev.slice(0, okmBytes.length - cur), cur);
        cur += okmBytes.length - cur;
      }
    }
    return okm;
  }

  public async extractAndExpand(
    salt: ArrayBufferLike | ArrayBufferView,
    ikm: ArrayBufferLike | ArrayBufferView,
    info: ArrayBufferLike | ArrayBufferView,
    len: number,
  ): Promise<ArrayBuffer> {
    await this._setup();
    const ikmBuf = toArrayBuffer(ikm);
    const baseKey = await (this._api as SubtleCrypto).importKey(
      "raw",
      ikmBuf,
      "HKDF",
      false,
      ["deriveBits"],
    );
    return await (this._api as SubtleCrypto).deriveBits(
      {
        name: "HKDF",
        hash: this.algHash.hash,
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(info),
      },
      baseKey,
      len * 8,
    );
  }

  public async labeledExtract(
    salt: ArrayBufferLike | ArrayBufferView,
    label: Uint8Array,
    ikm: Uint8Array,
  ): Promise<ArrayBuffer> {
    return await this.extract(
      salt,
      this.buildLabeledIkm(label, ikm),
    );
  }

  public async labeledExpand(
    prk: ArrayBufferLike | ArrayBufferView,
    label: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Promise<ArrayBuffer> {
    return await this.expand(
      prk,
      this.buildLabeledInfo(label, info, len),
      len,
    );
  }

  protected _checkInit(): void {
    if (this._suiteId === EMPTY) {
      throw new Error("Not initialized. Call init()");
    }
  }
}

export class HkdfSha256Native extends HkdfNative {
  /** KdfId.HkdfSha256 (0x0001) */
  override id: KdfId = KdfId.HkdfSha256;
  /** 32 */
  override hashSize: number = 32;
  /** The parameters for Web Cryptography API */
  override algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-256",
    length: 256,
  };
}

export class HkdfSha384Native extends HkdfNative {
  /** KdfId.HkdfSha384 (0x0002) */
  override id: KdfId = KdfId.HkdfSha384;
  /** 48 */
  override hashSize: number = 48;
  /** The parameters for Web Cryptography API */
  override algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-384",
    length: 384,
  };
}

export class HkdfSha512Native extends HkdfNative {
  /** KdfId.HkdfSha512 (0x0003) */
  override id: KdfId = KdfId.HkdfSha512;
  /** 64 */
  override hashSize: number = 64;
  /** The parameters for Web Cryptography API */
  override algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-512",
    length: 512,
  };
}
