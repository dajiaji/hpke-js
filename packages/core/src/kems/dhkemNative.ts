import {
  Dhkem,
  EC_P_256,
  EC_P_384,
  EC_P_521,
  EcDhkemPrimitives,
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "@hpke/common";
import type { KemId } from "@hpke/common";

export class DhkemP256HkdfSha256Native extends Dhkem {
  override id: KemId = 0x0010; // KemId.DhkemP256HkdfSha256
  override secretSize: number = 32;
  override encSize: number = 65;
  override publicKeySize: number = 65;
  override privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256Native();
    const prim = new EcDhkemPrimitives(EC_P_256, kdf);
    // KemId.DhkemP256HkdfSha256
    super(0x0010, prim, kdf);
  }
}

export class DhkemP384HkdfSha384Native extends Dhkem {
  override id: KemId = 0x0011; // KemId.DhkemP384HkdfSha384
  override secretSize: number = 48;
  override encSize: number = 97;
  override publicKeySize: number = 97;
  override privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384Native();
    const prim = new EcDhkemPrimitives(EC_P_384, kdf);
    // KemId.DhkemP384HkdfSha384
    super(0x0011, prim, kdf);
  }
}

export class DhkemP521HkdfSha512Native extends Dhkem {
  override id: KemId = 0x0012; // KemId.DhkemP521HkdfSha512
  override secretSize: number = 64;
  override encSize: number = 133;
  override publicKeySize: number = 133;
  override privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512Native();
    const prim = new EcDhkemPrimitives(EC_P_521, kdf);
    // KemId.DhkemP521HkdfSha512
    super(0x0012, prim, kdf);
  }
}
