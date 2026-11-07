import type { KdfInterface } from "../interfaces/kdfInterface.ts";

import { EMPTY } from "../consts.ts";
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
  protected readonly _fallbackExtract:
    | ((salt: Uint8Array, ikm: Uint8Array) => Uint8Array)
    | undefined;

  /**
   * Uses WebCrypto HMAC for salts of any length when no callback is supplied.
   * Prefer omitting the callback and its JavaScript HMAC/SHA-2 imports to reduce
   * bundle size. Empty salts are normalized to hashSize zero bytes.
   *
   * @param fallbackExtract Optional legacy callback, taking precedence over
   * WebCrypto for nonempty salts whose length differs from hashSize.
   * Empty and hash-sized salts always use WebCrypto.
   */
  constructor(
    fallbackExtract?: (salt: Uint8Array, ikm: Uint8Array) => Uint8Array,
  ) {
    super();
    this._fallbackExtract = fallbackExtract;
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
    const ikmBuf = toArrayBuffer(ikm);
    if (
      saltBuf.byteLength !== this.hashSize &&
      this._fallbackExtract !== undefined
    ) {
      return this._fallbackExtract(
        new Uint8Array(saltBuf),
        new Uint8Array(ikmBuf),
      ).buffer as ArrayBuffer;
    }
    const key = await (this._api as SubtleCrypto).importKey(
      "raw",
      saltBuf,
      { name: this.algHash.name, hash: this.algHash.hash },
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
    if (len > 255 * this.hashSize) {
      throw new Error("Entropy limit reached");
    }
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

    const okm = new Uint8Array(len);
    let prev = EMPTY;
    const mid = toUint8Array(info);

    for (let counter = 1, offset = 0; offset < okm.length; counter++) {
      const input = new Uint8Array(prev.length + mid.length + 1);
      input.set(prev);
      input.set(mid, prev.length);
      input[input.length - 1] = counter;
      prev = new Uint8Array(
        await (this._api as SubtleCrypto).sign(
          "HMAC",
          key,
          input,
        ),
      );
      const block = prev.subarray(
        0,
        Math.min(prev.length, okm.length - offset),
      );
      okm.set(block, offset);
      offset += block.length;
    }
    return okm.buffer;
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
