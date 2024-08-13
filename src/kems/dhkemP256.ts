import { KemId } from "../../core/src/identifiers.ts";
import { HkdfSha256 } from "../kdfs/hkdfSha256.ts";
import { Dhkem } from "../../core/src/kems/dhkem.ts";
import { Ec } from "../../core/src/kems/dhkemPrimitives/ec.ts";

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
