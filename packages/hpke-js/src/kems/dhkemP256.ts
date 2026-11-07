import { Dhkem, EC_P_256, EcDhkemPrimitives } from "@hpke/common";
import type { KemId } from "@hpke/common";
import { HkdfSha256 } from "@hpke/dhkem-x25519";

export class DhkemP256HkdfSha256 extends Dhkem {
  override id: KemId = 0x0010; // KemId.DhkemP256HkdfSha256
  override secretSize: number = 32;
  override encSize: number = 65;
  override publicKeySize: number = 65;
  override privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new EcDhkemPrimitives(EC_P_256, kdf);
    // KemId.DhkemP256HkdfSha256
    super(0x0010, prim, kdf);
  }
}
