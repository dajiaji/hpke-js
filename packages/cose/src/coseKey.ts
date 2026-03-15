import type { CborValue } from "./cbor/types.ts";
import { encode } from "./cbor/encoder.ts";
import { decode } from "./cbor/decoder.ts";
import { CoseError } from "./errors.ts";

/** COSE_Key parameter labels (RFC 9052 / RFC 9053). */
const KeyLabel = {
  KTY: 1,
  KID: 2,
  ALG: 3,
  KEY_OPS: 4,
  CRV: -1,
  X: -2,
  Y: -3,
  D: -4,
} as const;

/** COSE key type values. */
export const CoseKty = {
  OKP: 1,
  EC2: 2,
} as const;

export type CoseKty = (typeof CoseKty)[keyof typeof CoseKty];

/** COSE EC curve identifiers. */
export const CoseCrv = {
  P256: 1,
  P384: 2,
  P521: 3,
  X25519: 4,
  X448: 5,
} as const;

export type CoseCrv = (typeof CoseCrv)[keyof typeof CoseCrv];

/** Expected coordinate sizes per curve. */
const CRV_KEY_SIZES: Record<number, number> = {
  [CoseCrv.P256]: 32,
  [CoseCrv.P384]: 48,
  [CoseCrv.P521]: 66,
  [CoseCrv.X25519]: 32,
  [CoseCrv.X448]: 56,
};

/** Valid kty for each curve. */
const CRV_KTY: Record<number, number> = {
  [CoseCrv.P256]: CoseKty.EC2,
  [CoseCrv.P384]: CoseKty.EC2,
  [CoseCrv.P521]: CoseKty.EC2,
  [CoseCrv.X25519]: CoseKty.OKP,
  [CoseCrv.X448]: CoseKty.OKP,
};

/** COSE key_ops values relevant to HPKE. */
const KeyOps = {
  DERIVE_BITS: 8,
} as const;

/** Parsed COSE_Key metadata. */
interface ParsedCoseKey {
  map: Map<CborValue, CborValue>;
  kty: CoseKty;
  crv: CoseCrv;
}

function parseCoseKeyMap(coseKeyBytes: Uint8Array): ParsedCoseKey {
  const map = decode(coseKeyBytes);
  if (!(map instanceof Map)) {
    throw new CoseError("COSE_Key is not a CBOR map");
  }

  const kty = map.get(KeyLabel.KTY);
  if (typeof kty !== "number" || (kty !== CoseKty.OKP && kty !== CoseKty.EC2)) {
    throw new CoseError(
      `Invalid or unsupported kty: ${kty} (expected OKP=1 or EC2=2)`,
    );
  }

  const crv = map.get(KeyLabel.CRV);
  if (typeof crv !== "number" || !(crv in CRV_KTY)) {
    throw new CoseError(
      `Invalid or unsupported crv: ${crv}`,
    );
  }

  // Validate kty/crv consistency
  const expectedKty = CRV_KTY[crv];
  if (kty !== expectedKty) {
    throw new CoseError(
      `kty/crv mismatch: kty=${kty} but crv=${crv} requires kty=${expectedKty}`,
    );
  }

  // Validate key_ops if present
  const keyOps = map.get(KeyLabel.KEY_OPS);
  if (keyOps !== undefined) {
    if (!Array.isArray(keyOps)) {
      throw new CoseError("key_ops must be an array");
    }
    const hasD = map.has(KeyLabel.D);
    if (hasD) {
      // Private key: key_ops MUST include "derive bits" (8)
      if (!keyOps.includes(KeyOps.DERIVE_BITS)) {
        throw new CoseError(
          "Private key key_ops must include 'derive bits' (8)",
        );
      }
    }
  }

  return { map, kty: kty as CoseKty, crv: crv as CoseCrv };
}

function validateCoordinateSize(
  name: string,
  data: Uint8Array,
  crv: CoseCrv,
): void {
  const expected = CRV_KEY_SIZES[crv];
  if (expected !== undefined && data.length !== expected) {
    throw new CoseError(
      `${name} length ${data.length} does not match crv expectation ${expected}`,
    );
  }
}

/**
 * Parse a CBOR-encoded COSE_Key and extract the raw private key bytes (d parameter).
 * Validates kty, crv, key length consistency.
 *
 * @param coseKeyBytes CBOR-encoded COSE_Key.
 * @returns The raw private key bytes.
 */
export function extractPrivateKeyBytes(coseKeyBytes: Uint8Array): Uint8Array {
  const { map, crv } = parseCoseKeyMap(coseKeyBytes);
  const d = map.get(KeyLabel.D);
  if (!(d instanceof Uint8Array)) {
    throw new CoseError("COSE_Key does not contain a private key (d)");
  }
  validateCoordinateSize("d", d, crv);
  return d;
}

/**
 * Parse a CBOR-encoded COSE_Key and extract the raw public key bytes.
 * Validates kty, crv, key length consistency.
 *
 * For EC2 keys (P-256/P-384/P-521): returns uncompressed point (0x04 || x || y).
 * For OKP keys (X25519/X448): returns x coordinate.
 *
 * @param coseKeyBytes CBOR-encoded COSE_Key.
 * @returns The raw public key bytes.
 */
export function extractPublicKeyBytes(coseKeyBytes: Uint8Array): Uint8Array {
  const { map, kty, crv } = parseCoseKeyMap(coseKeyBytes);
  const x = map.get(KeyLabel.X);
  if (!(x instanceof Uint8Array)) {
    throw new CoseError("COSE_Key does not contain x coordinate");
  }
  validateCoordinateSize("x", x, crv);

  if (kty === CoseKty.EC2) {
    const y = map.get(KeyLabel.Y);
    if (!(y instanceof Uint8Array)) {
      throw new CoseError("EC2 COSE_Key does not contain y coordinate");
    }
    validateCoordinateSize("y", y, crv);
    const result = new Uint8Array(1 + x.length + y.length);
    result[0] = 0x04;
    result.set(x, 1);
    result.set(y, 1 + x.length);
    return result;
  }
  // OKP: raw x coordinate
  return x;
}

/**
 * Get the curve identifier from a CBOR-encoded COSE_Key.
 * Validates kty/crv consistency.
 *
 * @param coseKeyBytes CBOR-encoded COSE_Key.
 * @returns The COSE curve identifier.
 */
export function extractCurve(coseKeyBytes: Uint8Array): CoseCrv {
  const { crv } = parseCoseKeyMap(coseKeyBytes);
  return crv;
}

/** Options for building a COSE_Key. */
export interface CoseKeyBuildOptions {
  kid?: Uint8Array;
  alg?: number;
}

/**
 * Build a CBOR-encoded COSE_Key for an EC2 key (P-256/P-384/P-521).
 */
export function buildEc2CoseKey(
  crv: CoseCrv,
  x: Uint8Array,
  y: Uint8Array,
  d?: Uint8Array,
  options?: CoseKeyBuildOptions,
): Uint8Array {
  const map = new Map<CborValue, CborValue>();
  map.set(KeyLabel.KTY, CoseKty.EC2);
  if (options?.kid) {
    map.set(KeyLabel.KID, options.kid);
  }
  if (options?.alg !== undefined) {
    map.set(KeyLabel.ALG, options.alg);
  }
  map.set(KeyLabel.CRV, crv);
  map.set(KeyLabel.X, x);
  map.set(KeyLabel.Y, y);
  if (d) {
    map.set(KeyLabel.D, d);
  }
  return encode(map);
}

/**
 * Build a CBOR-encoded COSE_Key for an OKP key (X25519/X448).
 */
export function buildOkpCoseKey(
  crv: CoseCrv,
  x: Uint8Array,
  d?: Uint8Array,
  options?: CoseKeyBuildOptions,
): Uint8Array {
  const map = new Map<CborValue, CborValue>();
  map.set(KeyLabel.KTY, CoseKty.OKP);
  if (options?.kid) {
    map.set(KeyLabel.KID, options.kid);
  }
  if (options?.alg !== undefined) {
    map.set(KeyLabel.ALG, options.alg);
  }
  map.set(KeyLabel.CRV, crv);
  map.set(KeyLabel.X, x);
  if (d) {
    map.set(KeyLabel.D, d);
  }
  return encode(map);
}
