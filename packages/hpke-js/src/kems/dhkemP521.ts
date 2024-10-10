import { Dhkem, Ec, KemId } from "@hpke/common";

import { HkdfSha512 } from "@hpke/dhkem-x448";

export class DhkemP521HkdfSha512 extends Dhkem {
  override id: KemId = KemId.DhkemP521HkdfSha512;
  override secretSize: number = 64;
  override encSize: number = 133;
  override publicKeySize: number = 133;
  override privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512();
    const prim = new Ec(KemId.DhkemP521HkdfSha512, kdf);
    super(KemId.DhkemP521HkdfSha512, prim, kdf);
  }
}
