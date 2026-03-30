import { HkdfSha384Native, hmac, sha384 } from "@hpke/common";

export class HkdfSha384 extends HkdfSha384Native {
  constructor() {
    super((salt, ikm) => hmac(sha384, salt, ikm));
  }
}
