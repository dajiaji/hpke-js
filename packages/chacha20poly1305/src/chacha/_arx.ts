/**
 * This file is based on noble-ciphers (https://github.com/paulmillr/noble-ciphers).
 *
 * noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-ciphers/blob/749cdf9cd07ebdd19e9b957d0f172f1045179695/src/_arx.ts
 */

/**
 * ChaCha20-specific helpers.

RFC 8439 ChaCha20 uses a 32-byte key, a 12-byte nonce and a 32-bit block
counter. The AEAD construction uses the same key/nonce twice: the Poly1305
one-time key is taken from the keystream block with counter 0, and the message
is encrypted starting from counter 1. The initial counter is therefore passed
explicitly instead of being kept as mutable state.

 * @module
 */
import {
  abytes,
  clean,
  copyBytes,
  isAligned32,
  u32,
  type XorStream,
} from "./utils.ts";

/** "expand 32-byte k" as Uint32Array (ChaCha20 sigma constant). */
export const sigma32_32 = Uint32Array.of(
  0x61707865,
  0x3320646e,
  0x79622d32,
  0x6b206574,
);

/** Rotate left. */
export function rotl(a: number, b: number): number {
  return (a << b) | (a >>> (32 - b));
}

/** Ciphers must use u32 for efficiency. */
export type CipherCoreFn = (
  sigma: Uint32Array,
  key: Uint32Array,
  nonce: Uint32Array,
  output: Uint32Array,
  counter: number,
  rounds?: number,
) => void;

// ChaCha20 block length is 512-bit
const BLOCK_LEN = 64;
const BLOCK_LEN32 = 16;

// new Uint32Array([2**32])   // => Uint32Array(1) [ 0 ]
// new Uint32Array([2**32-1]) // => Uint32Array(1) [ 4294967295 ]
const MAX_COUNTER = 2 ** 32 - 1;

const U32_EMPTY = Uint32Array.of();

function runCipher(
  core: CipherCoreFn,
  sigma: Uint32Array,
  key: Uint32Array,
  nonce: Uint32Array,
  data: Uint8Array,
  output: Uint8Array,
  counter: number,
): void {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u32(block);
  // Make sure that buffers aligned to 4 bytes
  const isAligned = isAligned32(data) && isAligned32(output);
  const d32 = isAligned ? u32(data) : U32_EMPTY;
  const o32 = isAligned ? u32(output) : U32_EMPTY;
  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, 20);
    if (counter >= MAX_COUNTER) throw new Error("arx: counter overflow");
    const take = Math.min(BLOCK_LEN, len - pos);
    // aligned to 4 bytes
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0) throw new Error("arx: invalid block position");
      for (let j = 0, posj: number; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}

/** Creates the RFC 8439 ChaCha20 cipher stream. */
export function createCipher(core: CipherCoreFn): XorStream {
  if (typeof core !== "function") throw new Error("core must be a function");
  return (
    key: Uint8Array,
    nonce: Uint8Array,
    data: Uint8Array,
    output?: Uint8Array,
    counter = 0,
  ): Uint8Array => {
    abytes(key, 32, "arx key");
    abytes(nonce, 12, "nonce");
    abytes(data, undefined, "data");
    const len = data.length;
    if (output === undefined) output = new Uint8Array(len);
    abytes(output, undefined, "output");
    if (
      !Number.isSafeInteger(counter) || counter < 0 || counter >= MAX_COUNTER
    ) {
      throw new Error("arx: counter overflow");
    }
    if (output.length < len) {
      throw new Error(
        `arx: output (${output.length}) is shorter than data (${len})`,
      );
    }
    const keyCopy = copyBytes(key);

    // Copy a misaligned nonce before creating a Uint32Array view.
    const nonceCopy = isAligned32(nonce) ? undefined : copyBytes(nonce);

    const k32 = u32(keyCopy);
    runCipher(
      core,
      sigma32_32,
      k32,
      u32(nonceCopy ?? nonce),
      data,
      output,
      counter,
    );
    clean(keyCopy);
    if (nonceCopy) clean(nonceCopy);
    return output;
  };
}
