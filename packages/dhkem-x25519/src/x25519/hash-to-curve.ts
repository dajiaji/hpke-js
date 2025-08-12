/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/abstract/hash-to-curve.ts
 */

/**
 * hash-to-curve from RFC 9380.
 * Hashes arbitrary-length byte strings to a list of one or more elements of a finite field F.
 * https://www.rfc-editor.org/rfc/rfc9380
 * @module
 */
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { asciiToBytes } from "./utils.ts";

export const _DST_scalar: Uint8Array = asciiToBytes("HashToScalar-");
