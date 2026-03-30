import { HkdfSha256Native, hmac, sha256 } from "@hpke/common";

export class HkdfSha256 extends HkdfSha256Native {
  constructor() {
    super((salt, ikm) => hmac(sha256, salt, ikm));
  }
}
