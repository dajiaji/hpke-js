import { Dhkem, Ec, KemId } from "@hpke/common";
import { HkdfSha384 } from "../kdfs/hkdfSha384.ts";

export class DhkemP384HkdfSha384 extends Dhkem {
  override id: KemId = KemId.DhkemP384HkdfSha384;
  override secretSize: number = 48;
  override encSize: number = 97;
  override publicKeySize: number = 97;
  override privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384();
    const prim = new Ec(KemId.DhkemP384HkdfSha384, kdf);
    super(KemId.DhkemP384HkdfSha384, prim, kdf);
  }
}
