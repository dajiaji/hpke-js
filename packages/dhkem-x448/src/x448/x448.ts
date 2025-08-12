/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/ed448.ts
 */

/**
 * Edwards448 (not Ed448-Goldilocks) curve with following addons:
 * - X448 ECDH
 * - Decaf cofactor elimination
 * - Elligator hash-to-group / point indistinguishability
 * Conforms to RFC 8032 https://www.rfc-editor.org/rfc/rfc8032.html#section-5.2
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import type { _DST_scalar } from "./hash-to-curve.ts";
import { mod, pow2 } from "./modular.ts";
import { montgomery, type MontgomeryECDH } from "./montgomery.ts";

// edwards448 curve
// a = 1n
// d = Fp.neg(39081n)
// Finite field 2n**448n - 2n**224n - 1n
// Subgroup order
// 2n**446n - 13818066809895115352007386748515426880336692474882178609894547503885n
const ed448_CURVE_p = BigInt(
  "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

// prettier-ignore
const _1n = BigInt(1),
  _2n = BigInt(2),
  _3n = BigInt(3),
  _11n = BigInt(11);
// prettier-ignore
const _22n = BigInt(22),
  _44n = BigInt(44),
  _88n = BigInt(88),
  _223n = BigInt(223);

// powPminus3div4 calculates z = x^k mod p, where k = (p-3)/4.
// Used for efficient square root calculation.
// ((P-3)/4).toString(2) would produce bits [223x 1, 0, 222x 1]
function ed448_pow_Pminus3div4(x: bigint): bigint {
  const P = ed448_CURVE_p;
  const b2 = (x * x * x) % P;
  const b3 = (b2 * b2 * x) % P;
  const b6 = (pow2(b3, _3n, P) * b3) % P;
  const b9 = (pow2(b6, _3n, P) * b3) % P;
  const b11 = (pow2(b9, _2n, P) * b2) % P;
  const b22 = (pow2(b11, _11n, P) * b11) % P;
  const b44 = (pow2(b22, _22n, P) * b22) % P;
  const b88 = (pow2(b44, _44n, P) * b44) % P;
  const b176 = (pow2(b88, _88n, P) * b88) % P;
  const b220 = (pow2(b176, _44n, P) * b44) % P;
  const b222 = (pow2(b220, _2n, P) * b2) % P;
  const b223 = (pow2(b222, _1n, P) * x) % P;
  return (pow2(b223, _223n, P) * b222) % P;
}

function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: Likewise, for X448, set the two least significant bits of the first byte to 0,
  bytes[0] &= 252; // 0b11111100
  // and the most significant bit of the last byte to 1.
  bytes[55] |= 128; // 0b10000000
  // NOTE: is NOOP for 56 bytes scalars (X25519/X448)
  bytes[56] = 0; // Byte outside of group (456 buts vs 448 bits)
  return bytes;
}

export const x448: MontgomeryECDH = /* @__PURE__ */ (() => {
  const P = ed448_CURVE_p;
  return montgomery({
    P,
    type: "x448",
    powPminus2: (x: bigint): bigint => {
      const Pminus3div4 = ed448_pow_Pminus3div4(x);
      const Pminus3 = pow2(Pminus3div4, _2n, P);
      return mod(Pminus3 * x, P); // Pminus3 * x = Pminus2
    },
    adjustScalarBytes,
  });
})();
