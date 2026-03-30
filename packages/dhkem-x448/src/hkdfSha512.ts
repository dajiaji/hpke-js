import { HkdfSha512Native, hmac, sha512 } from "@hpke/common";

export class HkdfSha512 extends HkdfSha512Native {
  constructor() {
    super((salt, ikm) => hmac(sha512, salt, ikm));
  }
}
