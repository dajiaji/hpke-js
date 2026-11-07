/**
 * This file is based on noble-ciphers (https://github.com/paulmillr/noble-ciphers).
 *
 * noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-ciphers/blob/749cdf9cd07ebdd19e9b957d0f172f1045179695/src/utils.ts
 */

/**
 * Byte utilities, input validation, and types for ChaCha20-Poly1305.
 * @module
 */
import { abytes, clean, copyBytes, createView, isLE, u32 } from "@hpke/common";

export { abytes, clean, copyBytes, createView, isLE, u32 };

/** ChaCha20-Poly1305 cipher with an optional caller-provided output buffer. */
export type CipherWithOutput = {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};

export type ChaCha20Poly1305Cipher =
  & ((key: Uint8Array, nonce: Uint8Array, AAD?: Uint8Array) => CipherWithOutput)
  & { blockSize: number; nonceLength: number; tagLength: number };

/** Validates ChaCha20-Poly1305 inputs and prevents repeated encryption. */
export function wrapCipher(
  constructor: (
    key: Uint8Array,
    nonce: Uint8Array,
    AAD?: Uint8Array,
  ) => CipherWithOutput,
): ChaCha20Poly1305Cipher {
  function wrappedCipher(
    key: Uint8Array,
    nonce: Uint8Array,
    AAD?: Uint8Array,
  ): CipherWithOutput {
    abytes(key, undefined, "key");
    if (!isLE) {
      throw new Error("Non little-endian hardware is not yet supported");
    }
    abytes(nonce, 12, "nonce");
    if (AAD !== undefined) abytes(AAD, undefined, "AAD");
    const cipher = constructor(key, nonce, AAD);
    let called = false;
    return {
      encrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
        if (called) {
          throw new Error("cannot encrypt() twice with same key + nonce");
        }
        called = true;
        abytes(data);
        if (output !== undefined) abytes(output, undefined, "output");
        return cipher.encrypt(data, output);
      },
      decrypt(data: Uint8Array, output?: Uint8Array): Uint8Array {
        abytes(data);
        if (data.length < 16) {
          throw new Error(
            '"ciphertext" expected length bigger than tagLength=16',
          );
        }
        if (output !== undefined) abytes(output, undefined, "output");
        return cipher.decrypt(data, output);
      },
    };
  }
  return Object.assign(wrappedCipher, {
    blockSize: 64,
    nonceLength: 12,
    tagLength: 16,
  });
}

/** ChaCha20 XOR stream with an optional output buffer and initial counter. */
export type XorStream = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output?: Uint8Array,
  counter?: number,
) => Uint8Array;

/** Compares 2 uint8array-s in kinda constant time. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * By default, returns u8a of length.
 * When out is available, it checks it for validity and uses it.
 */
export function getOutput(
  expectedLength: number,
  out?: Uint8Array,
  onlyAligned = true,
): Uint8Array {
  if (out === undefined) return new Uint8Array(expectedLength);
  if (out.length !== expectedLength) {
    throw new Error(
      '"output" expected Uint8Array of length ' + expectedLength + ", got: " +
        out.length,
    );
  }
  if (onlyAligned && !isAligned32(out)) {
    throw new Error("invalid output, must be aligned");
  }
  return out;
}

// Is byte array aligned to 4 byte offset (u32)?
export function isAligned32(bytes: Uint8Array): boolean {
  return bytes.byteOffset % 4 === 0;
}

// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
// Re-exported from @hpke/common.
