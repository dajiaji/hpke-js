import { hmac } from "npm:@noble/hashes@1.3.1/hmac";
import { sha256 } from "npm:@noble/hashes@1.3.1/sha256";
import { sha384, sha512 } from "npm:@noble/hashes@1.3.1/sha512";

import type { KdfInterface } from "../interfaces/kdfInterface.ts";

import { KdfId } from "../identifiers.ts";
import { KdfAlgorithm } from "../algorithm.ts";

import * as consts from "../consts.ts";

export class Hkdf extends KdfAlgorithm implements KdfInterface {
  public readonly id: KdfId = KdfId.HkdfSha256;
  public readonly hashSize: number = 0;
  protected readonly algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-256",
    length: 256,
  };

  constructor() {
    super();
  }

  public buildLabeledIkm(label: Uint8Array, ikm: Uint8Array): Uint8Array {
    const ret = new Uint8Array(
      7 + this._suiteId.byteLength + label.byteLength + ikm.byteLength,
    );
    ret.set(consts.HPKE_VERSION, 0);
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
    const ret = new Uint8Array(
      9 + this._suiteId.byteLength + label.byteLength + info.byteLength,
    );
    ret.set(new Uint8Array([0, len]), 0);
    ret.set(consts.HPKE_VERSION, 2);
    ret.set(this._suiteId, 9);
    ret.set(label, 9 + this._suiteId.byteLength);
    ret.set(info, 9 + this._suiteId.byteLength + label.byteLength);
    return ret;
  }

  public async extract(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    this.checkInit();
    if (salt.byteLength === 0) {
      salt = new ArrayBuffer(this.hashSize);
    }
    if (salt.byteLength !== this.hashSize) {
      // Web Cryptography API supports only Nh(hashSize) length key.
      // In this case, fallback to the upper-layer hmac library.
      switch (this.algHash.hash) {
        case "SHA-256":
          return hmac(
            sha256,
            new Uint8Array(salt),
            new Uint8Array(ikm),
          );
        case "SHA-384":
          return hmac(
            sha384,
            new Uint8Array(salt),
            new Uint8Array(ikm),
          );
        default:
          // case "SHA-512":
          return hmac(
            sha512,
            new Uint8Array(salt),
            new Uint8Array(ikm),
          );
      }
    }
    const key = await (this._api as SubtleCrypto).importKey(
      "raw",
      salt,
      this.algHash,
      false,
      [
        "sign",
      ],
    );
    return await (this._api as SubtleCrypto).sign("HMAC", key, ikm);
  }

  public async expand(
    prk: ArrayBuffer,
    info: ArrayBuffer,
    len: number,
  ): Promise<ArrayBuffer> {
    this.checkInit();
    const key = await (this._api as SubtleCrypto).importKey(
      "raw",
      prk,
      this.algHash,
      false,
      [
        "sign",
      ],
    );

    const okm = new ArrayBuffer(len);
    const p = new Uint8Array(okm);
    let prev = consts.EMPTY;
    const mid = new Uint8Array(info);
    const tail = new Uint8Array(1);

    if (len > 255 * this.hashSize) {
      throw new Error("Entropy limit reached");
    }

    const tmp = new Uint8Array(this.hashSize + mid.length + 1);
    for (let i = 1, cur = 0; cur < p.length; i++) {
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
    this.checkInit();
    const baseKey = await (this._api as SubtleCrypto).importKey(
      "raw",
      ikm,
      "HKDF",
      false,
      consts.KEM_USAGES,
    );
    return await (this._api as SubtleCrypto).deriveBits(
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

export class HkdfSha256 extends Hkdf implements KdfInterface {
  public readonly id: KdfId = KdfId.HkdfSha256;
  public readonly hashSize: number = 32;
  protected readonly algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-256",
    length: 256,
  };
}

export class HkdfSha384 extends Hkdf implements KdfInterface {
  public readonly id: KdfId = KdfId.HkdfSha384;
  public readonly hashSize: number = 48;
  protected readonly algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-384",
    length: 384,
  };
}

export class HkdfSha512 extends Hkdf implements KdfInterface {
  public readonly id: KdfId = KdfId.HkdfSha512;
  public readonly hashSize: number = 64;
  protected readonly algHash: HmacKeyGenParams = {
    name: "HMAC",
    hash: "SHA-512",
    length: 512,
  };
}
