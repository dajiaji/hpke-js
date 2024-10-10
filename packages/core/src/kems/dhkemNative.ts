import {
  Dhkem,
  Ec,
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
  KemId,
} from "@hpke/common";

export class DhkemP256HkdfSha256Native extends Dhkem {
  override id: KemId = KemId.DhkemP256HkdfSha256;
  override secretSize: number = 32;
  override encSize: number = 65;
  override publicKeySize: number = 65;
  override privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256Native();
    const prim = new Ec(KemId.DhkemP256HkdfSha256, kdf);
    super(KemId.DhkemP256HkdfSha256, prim, kdf);
  }
}

export class DhkemP384HkdfSha384Native extends Dhkem {
  override id: KemId = KemId.DhkemP384HkdfSha384;
  override secretSize: number = 48;
  override encSize: number = 97;
  override publicKeySize: number = 97;
  override privateKeySize: number = 48;

  constructor() {
    const kdf = new HkdfSha384Native();
    const prim = new Ec(KemId.DhkemP384HkdfSha384, kdf);
    super(KemId.DhkemP384HkdfSha384, prim, kdf);
  }
}

export class DhkemP521HkdfSha512Native extends Dhkem {
  override id: KemId = KemId.DhkemP521HkdfSha512;
  override secretSize: number = 64;
  override encSize: number = 133;
  override publicKeySize: number = 133;
  override privateKeySize: number = 64;

  constructor() {
    const kdf = new HkdfSha512Native();
    const prim = new Ec(KemId.DhkemP521HkdfSha512, kdf);
    super(KemId.DhkemP521HkdfSha512, prim, kdf);
  }
}
