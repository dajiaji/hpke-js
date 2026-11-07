import { Dhkem, EC_P_521, EcDhkemPrimitives } from "@hpke/common";
import type { KemId } from "@hpke/common";

import { HkdfSha512 } from "@hpke/dhkem-x448";

export class DhkemP521HkdfSha512 extends Dhkem {
  override id: KemId = 0x0012; // KemId.DhkemP521HkdfSha512
  override secretSize: number = 64;
  override encSize: number = 133;
  override publicKeySize: number = 133;
  override privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512();
    const prim = new EcDhkemPrimitives(EC_P_521, kdf);
    // KemId.DhkemP521HkdfSha512
    super(0x0012, prim, kdf);
  }
}
