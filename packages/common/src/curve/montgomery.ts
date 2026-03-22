/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/abstract/montgomery.ts
 */

/**
 * Montgomery curve methods. It's not really whole montgomery curve,
 * just bunch of very specific methods for X25519 / X448 from
 * [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  abytes,
  aInRange,
  bytesToNumberLE,
  copyBytes,
  type CryptoKeys,
  numberToBytesLE,
  randomBytes,
  validateObject,
} from "../utils/noble.ts";
import { createKeygen, type CurveLengths } from "./curve.ts";
import { mod } from "./modular.ts";
import { N_0, N_1, N_2 } from "../consts.ts";

export type CurveType = {
  P: bigint; // finite field prime
  type: "x25519" | "x448";
  adjustScalarBytes: (bytes: Uint8Array) => Uint8Array;
  powPminus2: (x: bigint) => bigint;
  randomBytes?: (bytesLength?: number) => Uint8Array;
};

export type MontgomeryECDH = {
  scalarMult: (scalar: Uint8Array, u: Uint8Array) => Uint8Array;
  scalarMultBase: (scalar: Uint8Array) => Uint8Array;
  getSharedSecret: (
    secretKeyA: Uint8Array,
    publicKeyB: Uint8Array,
  ) => Uint8Array;
  getPublicKey: (secretKey: Uint8Array) => Uint8Array;
  utils: {
    randomSecretKey: (seed?: Uint8Array) => Uint8Array;
  };
  GuBytes: Uint8Array;
  lengths: CurveLengths;
  keygen: (
    seed?: Uint8Array,
  ) => { secretKey: Uint8Array; publicKey: Uint8Array };
};

function validateOpts(curve: CurveType) {
  validateObject(curve, {
    adjustScalarBytes: "function",
    powPminus2: "function",
  });
  return Object.freeze({ ...curve } as const);
}

export function montgomery(curveDef: CurveType): MontgomeryECDH {
  const CURVE = validateOpts(curveDef);
  const { P, type, adjustScalarBytes, powPminus2, randomBytes: rand } = CURVE;
  const is25519 = type === "x25519";
  if (!is25519 && type !== "x448") throw new Error("invalid type");
  const randomBytes_ = rand || randomBytes;

  const montgomeryBits = is25519 ? 255 : 448;
  const fieldLen = is25519 ? 32 : 56;
  const Gu = is25519 ? 9n : 5n;
  // RFC 7748 #5:
  // The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519 and
  // (156326 - 2) / 4 = 39081 for curve448/X448
  // const a = is25519 ? 156326n : 486662n;
  const a24 = is25519 ? 121665n : 39081n;
  // RFC: x25519 "the resulting integer is of the form 2^254 plus
  // eight times a value between 0 and 2^251 - 1 (inclusive)"
  // x448: "2^447 plus four times a value between 0 and 2^445 - 1 (inclusive)"
  const minScalar = is25519 ? N_2 ** 254n : N_2 ** 447n;
  const maxAdded = is25519 ? 8n * N_2 ** 251n - N_1 : 4n * N_2 ** 445n - N_1;
  const maxScalar = minScalar + maxAdded + N_1; // (inclusive)
  const modP = (n: bigint) => mod(n, P);
  const GuBytes = encodeU(Gu);
  function encodeU(u: bigint): Uint8Array {
    return numberToBytesLE(modP(u), fieldLen);
  }
  // Mask for clearing bit 255 (x25519): (1n << 255n) - 1n
  const uMask = is25519 ? (N_1 << 255n) - N_1 : N_0;
  function decodeU(u: Uint8Array): bigint {
    abytes(u, fieldLen, "uCoordinate");
    let n = bytesToNumberLE(u);
    // RFC: When receiving such an array, implementations of X25519
    // (but not X448) MUST mask the most significant bit in the final byte.
    if (is25519) n &= uMask;
    // RFC: Implementations MUST accept non-canonical values and process them as
    // if they had been reduced modulo the field prime.  The non-canonical
    // values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
    // - 1 through 2^448 - 1 for X448.
    return modP(n);
  }
  function decodeScalar(scalar: Uint8Array): bigint {
    return bytesToNumberLE(
      adjustScalarBytes(copyBytes(abytes(scalar, fieldLen, "scalar"))),
    );
  }
  function scalarMult(scalar: Uint8Array, u: Uint8Array): Uint8Array {
    const pu = montgomeryLadder(decodeU(u), decodeScalar(scalar));
    // Some public keys are useless, of low-order. Curve author doesn't think
    // it needs to be validated, but we do it nonetheless.
    // https://cr.yp.to/ecdh.html#validate
    if (pu === N_0) throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  // Pre-decoded base point u-coordinate (avoids redundant decode on every call)
  const GuDecoded = modP(Gu);
  // Computes public key from private. By doing scalar multiplication of base point.
  function scalarMultBase(scalar: Uint8Array): Uint8Array {
    const pu = montgomeryLadder(GuDecoded, decodeScalar(scalar));
    if (pu === N_0) throw new Error("invalid private or public key received");
    return encodeU(pu);
  }
  const getPublicKey = scalarMultBase;
  const getSharedSecret = scalarMult;

  /**
   * Montgomery x-only multiplication ladder.
   * cswap is inlined to avoid per-iteration object allocations.
   * Loop counter uses number instead of bigint to avoid BigInt arithmetic overhead.
   * @param pointU u coordinate (x) on Montgomery Curve 25519
   * @param scalar by which the point would be multiplied
   * @returns new Point on Montgomery curve
   */
  function montgomeryLadder(u: bigint, scalar: bigint): bigint {
    aInRange("u", u, N_0, P);
    aInRange("scalar", scalar, minScalar, maxScalar);
    const k = scalar;
    const x_1 = u;
    let x_2 = N_1;
    let z_2 = N_0;
    let x_3 = u;
    let z_3 = N_1;
    let swap = N_0;
    let dummy: bigint;
    for (let t = montgomeryBits - 1; t >= 0; t--) {
      const k_t = (k >> BigInt(t)) & N_1;
      swap ^= k_t;
      // Masked cswap (best-effort constant-time for BigInt).
      // Only dummy needs modP; x/z reductions are deferred to the
      // subsequent multiplications in the ladder body.
      dummy = modP(swap * (x_2 - x_3));
      x_2 -= dummy;
      x_3 += dummy;
      dummy = modP(swap * (z_2 - z_3));
      z_2 -= dummy;
      z_3 += dummy;
      swap = k_t;

      const A = x_2 + z_2;
      const AA = modP(A * A);
      const B = x_2 - z_2;
      const BB = modP(B * B);
      const E = AA - BB;
      const C = x_3 + z_3;
      const D = x_3 - z_3;
      const DA = modP(D * A);
      const CB = modP(C * B);
      const dacb = DA + CB;
      const da_cb = DA - CB;
      x_3 = modP(dacb * dacb);
      z_3 = modP(x_1 * modP(da_cb * da_cb));
      x_2 = modP(AA * BB);
      // a24 is small (17-bit for x25519, 16-bit for x448), so a24 * E adds
      // only ~17 bits beyond P — negligible impact on the outer multiplication.
      z_2 = modP(E * (AA + a24 * E));
    }
    // Final masked cswap
    dummy = modP(swap * (x_2 - x_3));
    x_2 -= dummy;
    x_3 += dummy;
    dummy = modP(swap * (z_2 - z_3));
    z_2 -= dummy;
    z_3 += dummy;
    const z2 = powPminus2(z_2); // `Fp.pow(x, P - N_2)` is much slower equivalent
    return modP(x_2 * z2); // Return x_2 * (z_2^(p - 2))
  }
  const lengths = {
    secretKey: fieldLen,
    publicKey: fieldLen,
    seed: fieldLen,
  };
  const randomSecretKey = (seed?: Uint8Array) => {
    if (seed === undefined) {
      seed = randomBytes_(fieldLen);
    }
    abytes(seed, lengths.seed, "seed");
    return seed;
  };
  const utils = { randomSecretKey };

  return Object.freeze({
    keygen: createKeygen(randomSecretKey, getPublicKey),
    getSharedSecret,
    getPublicKey,
    scalarMult,
    scalarMultBase,
    utils,
    GuBytes: GuBytes.slice(),
    lengths,
  }) satisfies CryptoKeys;
}
