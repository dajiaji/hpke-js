import { KemId } from "../identifiers.ts";
import {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "../kdfs/hkdf.ts";
import { Dhkem } from "./dhkem.ts";
import { Ec } from "./dhkemPrimitives/ec.ts";

export class DhkemP256HkdfSha256Native extends Dhkem {
  public readonly id: KemId = KemId.DhkemP256HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 65;
  public readonly publicKeySize: number = 65;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256Native();
    const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
    super(prim, kdf);
  }
}

export class DhkemP384HkdfSha384Native extends Dhkem {
  public readonly id: KemId = KemId.DhkemP384HkdfSha384;
  public readonly secretSize: number = 48;
  public readonly encSize: number = 97;
  public readonly publicKeySize: number = 97;
  public readonly privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384Native();
    const prim = new Ec(KemId.DhkemP384HkdfSha384, kdf);
    super(prim, kdf);
  }
}

export class DhkemP521HkdfSha512Native extends Dhkem {
  public readonly id: KemId = KemId.DhkemP521HkdfSha512;
  public readonly secretSize: number = 64;
  public readonly encSize: number = 133;
  public readonly publicKeySize: number = 133;
  public readonly privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512Native();
    const prim = new Ec(KemId.DhkemP521HkdfSha512, kdf);
    super(prim, kdf);
  }
}
