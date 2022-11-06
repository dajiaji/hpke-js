import { hmac } from "./bundles/hmac/mod.ts";

import type { KdfInterface } from "./interfaces/kdfInterface.ts";

import { Kdf } from "./identifiers.ts";
import { WebCrypto } from "./webCrypto.ts";

import * as consts from "./consts.ts";
import * as errors from "../src/errors.ts";

export class KdfContext extends WebCrypto implements KdfInterface {
  public readonly id: Kdf;
  public readonly hashSize: number;
  protected readonly suiteId: Uint8Array;
  protected readonly algHash: HmacKeyGenParams;
  protected readonly _nH: number;

  constructor(api: SubtleCrypto, kdf: Kdf, suiteId: Uint8Array) {
    super(api);
    this.id = kdf;
    this.suiteId = suiteId;
    switch (kdf) {
      case Kdf.HkdfSha256:
        this.hashSize = 32;
        this.algHash = { name: "HMAC", hash: "SHA-256", length: 256 };
        break;
      case Kdf.HkdfSha384:
        this.hashSize = 48;
        this.algHash = { name: "HMAC", hash: "SHA-384", length: 384 };
        break;
      default:
        // case Kdf.HkdfSha512:
        this.hashSize = 64;
        this.algHash = { name: "HMAC", hash: "SHA-512", length: 512 };
        break;
    }
    if (this.algHash.length === undefined) {
      throw new Error("Unknown hash size.");
    }
    this._nH = this.algHash.length / 8;
  }

  public buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array {
    const ret = new Uint8Array(
      7 + this.suiteId.byteLength + label.byteLength + ikm.byteLength,
    );
    ret.set(consts.HPKE_VERSION, 0);
    ret.set(this.suiteId, 7);
    ret.set(label, 7 + this.suiteId.byteLength);
    ret.set(ikm, 7 + this.suiteId.byteLength + label.byteLength);
    return ret;
  }

  public buildLabeledInfo(
    label: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Uint8Array {
    const ret = new Uint8Array(
      9 + this.suiteId.byteLength + label.byteLength + info.byteLength,
    );
    ret.set(new Uint8Array([0, len]), 0);
    ret.set(consts.HPKE_VERSION, 2);
    ret.set(this.suiteId, 9);
    ret.set(label, 9 + this.suiteId.byteLength);
    ret.set(info, 9 + this.suiteId.byteLength + label.byteLength);
    return ret;
  }

  public async extract(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if (salt.byteLength === 0) {
      salt = new ArrayBuffer(this._nH);
    }
    if (salt.byteLength !== this._nH) {
      // Web Cryptography API supports only _nH length key.
      // In this case, fallback to the upper-layer hmac library.
      switch (this.algHash.hash) {
        case "SHA-256":
          return hmac(
            "sha256",
            new Uint8Array(salt),
            new Uint8Array(ikm),
          ) as Uint8Array;
        case "SHA-512":
          return hmac(
            "sha512",
            new Uint8Array(salt),
            new Uint8Array(ikm),
          ) as Uint8Array;
        default:
          throw new errors.NotSupportedError(
            `${this.algHash.hash} key length should be ${this._nH}.`,
          );
      }
    }
    const key = await this._api.importKey("raw", salt, this.algHash, false, [
      "sign",
    ]);
    return await this._api.sign("HMAC", key, ikm);
  }

  public async expand(
    prk: ArrayBuffer,
    info: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer> {
    const key = await this._api.importKey("raw", prk, this.algHash, false, [
      "sign",
    ]);

    const okm = new ArrayBuffer(len);
    const p = new Uint8Array(okm);
    let prev = consts.EMPTY;
    const mid = new Uint8Array(info);
    const tail = new Uint8Array(1);

    if (len > 255 * this._nH) {
      throw new Error("Entropy limit reached");
    }

    const tmp = new Uint8Array(this._nH + mid.length + 1);
    for (let i = 1, cur = 0; cur < p.length; i++) {
      tail[0] = i;
      tmp.set(prev, 0);
      tmp.set(mid, prev.length);
      tmp.set(tail, prev.length + mid.length);
      prev = new Uint8Array(
        await this._api.sign(
          "HMAC",
          key,
          tmp.slice(0, prev.length + mid.length + 1),
        ),
      );
      if (p.length - cur >= prev.length) {
        p.set(prev, cur);
        cur += prev.length;
      } else {
        p.set(prev.slice(0, p.length - cur), cur);
        cur += p.length - cur;
      }
    }
    return okm;
  }

  public async extractAndExpand(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
    info: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer> {
    const baseKey = await this._api.importKey(
      "raw",
      ikm,
      "HKDF",
      false,
      consts.KEM_USAGES,
    );
    return await this._api.deriveBits(
      {
        name: "HKDF",
        hash: this.algHash.hash,
        salt: salt,
        info: info,
      },
      baseKey,
      len * 8,
    );
  }

  public async labeledExtract(
    salt: ArrayBuffer,
    label: Uint8Array,
    ikm: Uint8Array,
  ): Promise<ArrayBuffer> {
    return await this.extract(salt, this.buildLabeledIkm(label, ikm));
  }

  public async labeledExpand(
    prk: ArrayBuffer,
    label: Uint8Array,
    info: Uint8Array,
    len: number,
  ): Promise<ArrayBuffer> {
    return await this.expand(prk, this.buildLabeledInfo(label, info, len), len);
  }
}
