/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/abstract/montgomery.ts
 * with the X25519/X448 timing hardening from
 * https://github.com/paulmillr/noble-curves/commit/c9a8031720412fad1006b4683dbffdf33d2cedf5
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

// cswap from RFC7748 "example code", adapted to BigInt.
//
// RFC: "dummy = mask(swap) AND (x_2 XOR x_3), where mask(swap) is the all-1 or all-0 word of the
// same length as x_2 and x_3". On fixed-width machine words both cases cost the same. BigInt has
// no fixed width, so a {0n, 1n} selector does not: V8 short-circuits `0n * v` - and, identically,
// `0n & v`, `v + 0n`, `v - 0n` - to a no-op, while `1n * v` is a real multiply. The ladder calls
// this with swap = k_t XOR k_(t+1), which would make total running time a linear function of how
// often adjacent bits of the secret scalar differ: remotely measurable, and worth ~4 bits of a
// long-term key.
//
// So select with a full-width mask instead, and interpolate rather than mask off a dummy.
// Ported from noble-curves:
// https://github.com/paulmillr/noble-curves/commit/c9a8031720412fad1006b4683dbffdf33d2cedf5

/**
 * Selector for cswap(): `P` to keep, `P + 1` to swap, chosen by the low bit of `swap`.
 * Higher bits are ignored, and `swap` is passed in whole rather than as a {0n, 1n} bit on
 * purpose: `P + (swap & 1n)` would short-circuit the addition whenever the bit is clear.
 * Subtracting `swap` with its low bit cleared keeps every operand full-width instead.
 */
function cmask(P: bigint, swap: bigint): bigint {
  return P + swap - ((swap >> N_1) << N_1);
}

/**
 * Swap two field elements when `mask` is `P + 1`, keep them when it is `P`:
 *
 *   d    = 6P + x_3 - x_2
 *   x_2' = d * mask + x_2   (mod P)      x_3' = (x_2 + x_3) - x_2'
 *
 * The extra `6P * mask` vanishes modulo P. The offset keeps the reduction dividend positive and
 * in one word-count band for both masks. JavaScript BigInt has no constant-time contract; this
 * removes the selector-dependent short-circuits, not every value-dependent timing difference.
 *
 * Both elements MUST already be reduced mod P; unreduced input corrupts the kept-side output.
 */
function cswap(
  P: bigint,
): (mask: bigint, x_2: bigint, x_3: bigint) => { x_2: bigint; x_3: bigint } {
  const offset = 6n * P;
  return (mask: bigint, x_2: bigint, x_3: bigint) => {
    const sum = x_2 + x_3;
    const d = offset + x_3 - x_2;
    const a = (d * mask + x_2) % P;
    return { x_2: a, x_3: sum - a };
  };
}

/** Internal helpers, exported for tests only. Not part of the public API. */
export const __TEST: { cmask: typeof cmask; cswap: typeof cswap } =
  /* @__PURE__ */ Object.freeze({ cmask, cswap });

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
  const swap = cswap(P);
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
  /**
   * u coordinates whose order divides the cofactor, on the curve and on its quadratic twist -
   * the ladder sends every one of them to zero. Same blocklist libsodium and post-CVE-2017-0379
   * Libgcrypt carry. decodeU() reduces mod P first, so the non-canonical encodings P and P + 1
   * collapse onto 0 and 1.
   */
  const lowOrderU = new Set(
    is25519
      ? [
        N_0,
        N_1,
        P - N_1,
        325606250916557431795983626356110631294008115727848805560023387167927233504n,
        39382357235489614581723060781553021112529911719440698176882885853963445705823n,
      ]
      : [N_0, N_1, P - N_1],
  );
  function scalarMult(scalar: Uint8Array, u: Uint8Array): Uint8Array {
    // Some public keys are useless, of low-order. Curve author doesn't think
    // it needs to be validated, but we do it nonetheless.
    // https://cr.yp.to/ecdh.html#validate
    //
    // Reject them BEFORE the ladder. Detecting them from the all-zero output
    // first runs all rounds against the long-term secret, handing an
    // unauthenticated attacker a free timing oracle. Low-order inputs also
    // drive the ladder into a degenerate state whose extra zero-operand
    // multiplications amplify any residual key-dependent timing.
    const pointU = decodeU(u);
    if (lowOrderU.has(pointU)) {
      throw new Error("invalid private or public key received");
    }
    const pu = montgomeryLadder(pointU, decodeScalar(scalar));
    // Unreachable for RFC 7748 clamped scalars; kept as defense in depth.
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
   * cswap uses full-width masks so the selector never short-circuits BigInt ops.
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
    // The RFC tracks `swap` across rounds to hold k_t XOR k_(t+1); the low
    // bit of `kx >> t` is the same value, without the carried state.
    // aInRange above pins bit (montgomeryBits - 1) of k set and everything
    // above it clear, so `kx >> t` is never zero and its width is a function
    // of t alone - never of a secret bit.
    const kx = k ^ (k >> N_1);
    for (let t = montgomeryBits - 1; t >= 0; t--) {
      const mask = cmask(P, kx >> BigInt(t));
      // swap() requires reduced inputs; every ladder state below is reduced.
      ({ x_2, x_3 } = swap(mask, x_2, x_3));
      ({ x_2: z_2, x_3: z_3 } = swap(mask, z_2, z_3));

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
    // trailing cswap: the RFC's `swap` holds k_0 here, which is the low bit of k
    const mask = cmask(P, k);
    ({ x_2, x_3 } = swap(mask, x_2, x_3));
    ({ x_2: z_2, x_3: z_3 } = swap(mask, z_2, z_3));
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
