import { Dhkem, Ec, KemId } from "@hpke/common";
import { HkdfSha256 } from "@hpke/dhkem-x25519";

export class DhkemP256HkdfSha256 extends Dhkem {
  public readonly id: KemId = KemId.DhkemP256HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 65;
  public readonly publicKeySize: number = 65;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
    super(KemId.DhkemP256HkdfSha256, prim, kdf);
  }
}
