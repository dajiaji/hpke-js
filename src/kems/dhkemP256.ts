import { KemId } from "../identifiers.ts";
import { HkdfSha256 } from "../kdfs/hkdf.ts";
import { Dhkem } from "./dhkem.ts";
import { Ec } from "./dhkemPrimitives/ec.ts";

export class DhkemP256HkdfSha256 extends Dhkem {
  public readonly id: KemId = KemId.DhkemP256HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 65;
  public readonly publicKeySize: number = 65;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
    super(prim, kdf);
  }
}
