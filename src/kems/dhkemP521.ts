import { KemId } from "../identifiers.ts";
import { HkdfSha512 } from "../kdfs/hkdfSha512.ts";
import { Dhkem } from "./dhkem.ts";
import { Ec } from "./dhkemPrimitives/ec.ts";

export class DhkemP521HkdfSha512 extends Dhkem {
  public readonly id: KemId = KemId.DhkemP521HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 133;
  public readonly publicKeySize: number = 133;
  public readonly privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512();
    const prim = new Ec(KemId.DhkemP521HkdfSha512, kdf);
    super(KemId.DhkemP521HkdfSha512, prim, kdf);
  }
}
