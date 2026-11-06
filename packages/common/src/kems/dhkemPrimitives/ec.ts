import type { KdfInterface } from "../../interfaces/kdfInterface.ts";

import { NotSupportedError } from "../../errors.ts";
import { KemId } from "../../identifiers.ts";
import {
  EC_P_256,
  EC_P_384,
  EC_P_521,
  type EcCurve,
  EcDhkemPrimitives,
} from "./ecDhkemPrimitives.ts";

function ecCurveOf(kem: KemId): EcCurve {
  switch (kem) {
    case KemId.DhkemP256HkdfSha256:
      return EC_P_256;
    case KemId.DhkemP384HkdfSha384:
      return EC_P_384;
    case KemId.DhkemP521HkdfSha512:
      return EC_P_521;
    default:
      throw new NotSupportedError(`Unsupported KEM ID for Ec: ${kem}`);
  }
}

/**
 * The DH-based KEM primitives for P-256, P-384 and P-521, selected by KEM ID.
 *
 * @deprecated Use {@link EcDhkemPrimitives} with {@link EC_P_256},
 * {@link EC_P_384} or {@link EC_P_521} instead. Selecting the curve by KEM ID
 * keeps the parameters of all curves in a bundle. This class is kept for
 * compatibility with existing `@hpke/*` packages and will be removed in the
 * next major version.
 */
export class Ec extends EcDhkemPrimitives {
  /**
   * @param kem The KEM ID (`DhkemP256HkdfSha256`, `DhkemP384HkdfSha384` or
   * `DhkemP521HkdfSha512`).
   * @param hkdf The KDF used for DeriveKeyPair.
   * @throws NotSupportedError if `kem` is not one of the above.
   */
  constructor(kem: KemId, hkdf: KdfInterface) {
    super(ecCurveOf(kem), hkdf);
  }
}
