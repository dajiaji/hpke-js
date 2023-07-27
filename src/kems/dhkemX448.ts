import { KemId } from "../identifiers.ts";
import { HkdfSha512 } from "../kdfs/hkdf.ts";
import { Dhkem } from "./dhkem.ts";
import { X448 } from "./dhkemPrimitives/x448.ts";

export class DhkemX448HkdfSha512 extends Dhkem {
  public readonly id: KemId = KemId.DhkemX448HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 56;
  public readonly publicKeySize: number = 56;
  public readonly privateKeySize: number = 56;

  constructor() {
    const kdf = new HkdfSha512();
    const prim = new X448(kdf);
    super(prim, kdf);
  }
}
