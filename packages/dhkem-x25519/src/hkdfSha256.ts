import { hmac } from "./hash/hmac.ts";
import { sha256 } from "./hash/sha2.ts";

import { HkdfSha256Native } from "@hpke/common";

export class HkdfSha256 extends HkdfSha256Native {
  public override async extract(
    salt: ArrayBuffer,
    ikm: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    await this._setup();
    if (salt.byteLength === 0) {
      salt = new ArrayBuffer(this.hashSize);
    }
    if (salt.byteLength !== this.hashSize) {
      return hmac(sha256, new Uint8Array(salt), new Uint8Array(ikm))
        .buffer as ArrayBuffer;
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
}
