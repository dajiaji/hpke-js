import { KemId } from "../identifiers.ts";
import { HkdfSha384 } from "../kdfs/hkdf.ts";
import { Dhkem } from "./dhkem.ts";
import { Ec } from "./dhkemPrimitives/ec.ts";

export class DhkemP384HkdfSha384 extends Dhkem {
  public readonly id: KemId = KemId.DhkemP384HkdfSha384;
  public readonly secretSize: number = 48;
  public readonly encSize: number = 97;
  public readonly publicKeySize: number = 97;
  public readonly privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384();
    const prim = new Ec(KemId.DhkemP384HkdfSha384, kdf);
    super(prim, kdf);
  }
}
