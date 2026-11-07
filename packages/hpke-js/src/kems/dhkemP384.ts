import { Dhkem, EC_P_384, EcDhkemPrimitives } from "@hpke/common";
import type { KemId } from "@hpke/common";
import { HkdfSha384 } from "../kdfs/hkdfSha384.ts";

export class DhkemP384HkdfSha384 extends Dhkem {
  override id: KemId = 0x0011; // KemId.DhkemP384HkdfSha384
  override secretSize: number = 48;
  override encSize: number = 97;
  override publicKeySize: number = 97;
  override privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384();
    const prim = new EcDhkemPrimitives(EC_P_384, kdf);
    // KemId.DhkemP384HkdfSha384
    super(0x0011, prim, kdf);
  }
}
