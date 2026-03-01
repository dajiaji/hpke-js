import { HkdfSha384Native, hmac, sha384, toArrayBuffer } from "@hpke/common";

export class HkdfSha384 extends HkdfSha384Native {
  public override async extract(
    salt: ArrayBufferLike | ArrayBufferView,
    ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<ArrayBuffer> {
    await this._setup();
    const saltBuf = salt.byteLength === 0
      ? new ArrayBuffer(this.hashSize)
      : toArrayBuffer(salt);
    const ikmBuf = toArrayBuffer(ikm);
    if (saltBuf.byteLength !== this.hashSize) {
      return hmac(sha384, new Uint8Array(saltBuf), new Uint8Array(ikmBuf))
        .buffer as ArrayBuffer;
    }
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
}
