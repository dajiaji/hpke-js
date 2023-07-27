import { KemId } from "../identifiers.ts";
import { HkdfSha256 } from "../kdfs/hkdf.ts";
import { Dhkem } from "./dhkem.ts";
import { X25519 } from "./dhkemPrimitives/x25519.ts";

export class DhkemX25519HkdfSha256 extends Dhkem {
  public readonly id: KemId = KemId.DhkemX25519HkdfSha256;
  public readonly secretSize: number = 32;
  public readonly encSize: number = 32;
  public readonly publicKeySize: number = 32;
  public readonly privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    const prim = new X25519(kdf);
    super(prim, kdf);
  }
}
