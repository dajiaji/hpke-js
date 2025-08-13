/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/abstract/curve.ts
 */

/**
 * Methods for elliptic curve multiplication by scalars.
 * Contains wNAF, pippenger.
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import type { Signer } from "../utils/noble.ts";

// import { Field, FpInvertBatch, type IField, validateField } from "./modular.ts";

export interface CurveLengths {
  secretKey?: number;
  publicKey?: number;
  publicKeyUncompressed?: number;
  publicKeyHasPrefix?: boolean;
  signature?: number;
  seed?: number;
}

type KeygenFn = (
  seed?: Uint8Array,
  isCompressed?: boolean,
) => { secretKey: Uint8Array; publicKey: Uint8Array };
export function createKeygen(
  // deno-lint-ignore ban-types
  randomSecretKey: Function,
  getPublicKey: Signer["getPublicKey"],
): KeygenFn {
  return function keygen(seed?: Uint8Array) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  };
}
