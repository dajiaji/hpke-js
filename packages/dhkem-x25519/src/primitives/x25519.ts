/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/ed25519.ts
 */

/**
 * ed25519 Twisted Edwards curve with following addons:
 * - X25519 ECDH
 * - Ristretto cofactor elimination
 * - Elligator hash-to-group / point indistinguishability
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { mod, montgomery, type MontgomeryECDH, pow2 } from "@hpke/common";

const _1n = 1n;
const _2n = 2n;
const _3n = 3n;
const _5n = 5n;

// P = 2n**255n - 19n
const ed25519_CURVE_p =
  0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffedn;

function ed25519_pow_2_252_3(x: bigint) {
  const _10n = 10n;
  const _20n = 20n;
  const _40n = 40n;
  const _80n = 80n;
  const P = ed25519_CURVE_p;
  const x2 = (x * x) % P;
  const b2 = (x2 * x) % P; // x^3, 11
  const b4 = (pow2(b2, _2n, P) * b2) % P; // x^15, 1111
  const b5 = (pow2(b4, _1n, P) * x) % P; // x^31
  const b10 = (pow2(b5, _5n, P) * b5) % P;
  const b20 = (pow2(b10, _10n, P) * b10) % P;
  const b40 = (pow2(b20, _20n, P) * b20) % P;
  const b80 = (pow2(b40, _40n, P) * b40) % P;
  const b160 = (pow2(b80, _80n, P) * b80) % P;
  const b240 = (pow2(b160, _80n, P) * b80) % P;
  const b250 = (pow2(b240, _10n, P) * b10) % P;
  const pow_p_5_8 = (pow2(b250, _2n, P) * x) % P;
  // ^ To pow to (p+3)/8, multiply it by x.
  return { pow_p_5_8, b2 };
}

function adjustScalarBytes(bytes: Uint8Array): Uint8Array {
  // Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
  // set the three least significant bits of the first byte
  bytes[0] &= 248; // 0b1111_1000
  // and the most significant bit of the last to zero,
  bytes[31] &= 127; // 0b0111_1111
  // set the second most significant bit of the last byte to 1
  bytes[31] |= 64; // 0b0100_0000
  return bytes;
}

export const x25519: MontgomeryECDH = /* @__PURE__ */ (() => {
  const P = ed25519_CURVE_p;
  return montgomery({
    P,
    type: "x25519",
    powPminus2: (x: bigint): bigint => {
      // x^(p-2) aka x^(2^255-21)
      const { pow_p_5_8, b2 } = ed25519_pow_2_252_3(x);
      return mod(pow2(pow_p_5_8, _3n, P) * b2, P);
    },
    adjustScalarBytes,
  });
})();
