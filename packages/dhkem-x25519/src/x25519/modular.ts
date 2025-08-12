/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/abstract/modular.ts
 */

/**
 * Utils for modular division and fields.
 * Field over 11 is a finite (Galois) field is integer number operations `mod 11`.
 * There is no division: it is replaced by modular multiplicative inverse.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */

// Numbers aren't used in x25519 / x448 builds
// prettier-ignore
const _0n = /* @__PURE__ */ BigInt(0);

// Calculates a modulo b
export function mod(a: bigint, b: bigint): bigint {
  const result = a % b;
  return result >= _0n ? result : b + result;
}

/** Does `x^(2^power)` mod p. `pow2(30, 4)` == `30^(2^4)` */
export function pow2(x: bigint, power: bigint, modulo: bigint): bigint {
  let res = x;
  while (power-- > _0n) {
    res *= res;
    res %= modulo;
  }
  return res;
}
