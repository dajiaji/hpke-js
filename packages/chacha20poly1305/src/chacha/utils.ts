/**
 * This file is based on noble-ciphers (https://github.com/paulmillr/noble-ciphers).
 *
 * noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-ciphers/blob/749cdf9cd07ebdd19e9b957d0f172f1045179695/src/utils.ts
 */

/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
import {
  abytes,
  aexists,
  anumber,
  aoutput,
  clean,
  copyBytes,
  createView,
  isLE,
  type TypedArray,
  u32,
} from "@hpke/common";

export {
  abytes,
  aexists,
  anumber,
  aoutput,
  clean,
  copyBytes,
  createView,
  isLE,
  type TypedArray,
  u32,
};

/** Asserts something is boolean. */
export function abool(b: boolean): void {
  if (typeof b !== "boolean") throw new Error(`boolean expected, not ${b}`);
}

/** Cast u8 / u16 / u32 to u8. */
export function u8(arr: TypedArray): Uint8Array {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}

// TODO: remove
export interface IHash2 {
  blockLen: number; // Bytes per block
  outputLen: number; // Bytes in output
  update(buf: string | Uint8Array): this;
  // Writes digest into buf
  digestInto(buf: Uint8Array): void;
  digest(): Uint8Array;
  /**
   * Resets internal state. Makes Hash instance unusable.
   * Reset is impossible for keyed hashes if key is consumed into state. If digest is not consumed
   * by user, they will need to manually call `destroy()` when zeroing is necessary.
   */
  destroy(): void;
}

// This will allow to re-use with composable things like packed & base encoders
// Also, we probably can make tags composable

/** Sync cipher: takes byte array and returns byte array. */
export type Cipher = {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
};

/** Cipher with `output` argument which can optimize by doing 1 less allocation. */
export type CipherWithOutput = Cipher & {
  encrypt(plaintext: Uint8Array, output?: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array, output?: Uint8Array): Uint8Array;
};

/**
 * Params are outside of return type, so it is accessible before calling constructor.
 * If function support multiple nonceLength's, we return the best one.
 */
type CipherParams = {
  blockSize: number;
  nonceLength?: number;
  tagLength?: number;
  varSizeNonce?: boolean;
};
/** ARX cipher, like salsa or chacha. */
export type ARXCipher =
  & ((
    key: Uint8Array,
    nonce: Uint8Array,
    AAD?: Uint8Array,
  ) => CipherWithOutput)
  & {
    blockSize: number;
    nonceLength: number;
    tagLength: number;
  };
// deno-lint-ignore no-explicit-any
type CipherCons<T extends any[]> = (
  key: Uint8Array,
  ...args: T
) => Cipher;
/**
 * Wraps a cipher: validates args, ensures encrypt() can only be called once.
 * @__NO_SIDE_EFFECTS__
 */
// deno-lint-ignore no-explicit-any
export const wrapCipher = <C extends CipherCons<any>, P extends CipherParams>(
  params: P,
  constructor: C,
): C & P => {
  // deno-lint-ignore no-explicit-any
  function wrappedCipher(key: Uint8Array, ...args: any[]): CipherWithOutput {
    // Validate key
    abytes(key, undefined, "key");

    // Big-Endian hardware is rare. Just in case someone still decides to run ciphers:
    if (!isLE) {
      throw new Error("Non little-endian hardware is not yet supported");
    }

    // Validate nonce if nonceLength is present
    if (params.nonceLength !== undefined) {
      const nonce = args[0];
      abytes(
        nonce,
        params.varSizeNonce ? undefined : params.nonceLength,
        "nonce",
      );
    }

    // Validate AAD if tagLength present
    const tagl = params.tagLength;
    if (tagl && args[1] !== undefined) abytes(args[1], undefined, "AAD");

    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength: number, output?: Uint8Array) => {
      if (output !== undefined) {
        if (fnLength !== 2) throw new Error("cipher output not supported");
        abytes(output, undefined, "output");
      }
    };
    // Create wrapped cipher with validation and single-use encryption
    let called = false;
    const wrCipher = {
      encrypt(data: Uint8Array, output?: Uint8Array) {
        if (called) {
          throw new Error("cannot encrypt() twice with same key + nonce");
        }
        called = true;
        abytes(data);
        checkOutput(cipher.encrypt.length, output);
        return (cipher as CipherWithOutput).encrypt(data, output);
      },
      decrypt(data: Uint8Array, output?: Uint8Array) {
        abytes(data);
        if (tagl && data.length < tagl) {
          throw new Error(
            '"ciphertext" expected length bigger than tagLength=' + tagl,
          );
        }
        checkOutput(cipher.decrypt.length, output);
        return (cipher as CipherWithOutput).decrypt(data, output);
      },
    };

    return wrCipher;
  }

  Object.assign(wrappedCipher, params);
  return wrappedCipher as C & P;
};

/** Represents salsa / chacha stream. */
export type XorStream = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  output?: Uint8Array,
  counter?: number,
) => Uint8Array;

// Used in ARX only
// deno-lint-ignore ban-types
type EmptyObj = {};

export function checkOpts<T1 extends EmptyObj, T2 extends EmptyObj>(
  defaults: T1,
  opts: T2,
): T1 & T2 {
  if (opts == null || typeof opts !== "object") {
    throw new Error("options must be defined");
  }
  const merged = Object.assign(defaults, opts);
  return merged as T1 & T2;
}

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

export function u64Lengths(
  dataLength: number,
  aadLength: number,
  isLE: boolean,
): Uint8Array {
  abool(isLE);
  const num = new Uint8Array(16);
  const view = createView(num);
  view.setBigUint64(0, BigInt(aadLength), isLE);
  view.setBigUint64(8, BigInt(dataLength), isLE);
  return num;
}

// Is byte array aligned to 4 byte offset (u32)?
export function isAligned32(bytes: Uint8Array): boolean {
  return bytes.byteOffset % 4 === 0;
}

// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
// Re-exported from @hpke/common.
