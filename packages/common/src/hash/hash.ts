/**
 * This file is based on noble-curves (https://github.com/paulmillr/noble-curves).
 *
 * noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-curves/blob/b9d49d2b41d550571a0c5be443ecb62109fa3373/src/utils.ts
 */

/**
 * Hash utilities and type definitions extracted from noble.ts
 * @module
 */

import { anumber } from "../utils/noble.ts";

export interface Hash<T> {
  blockLen: number; // Bytes per block
  outputLen: number; // Bytes in output
  update(buf: Uint8Array): this;
  digestInto(buf: Uint8Array): void;
  digest(): Uint8Array;
  destroy(): void;
  _cloneInto(to?: T): T;
  clone(): T;
}

export interface HashInfo {
  /** DER encoded OID in bytes */
  oid?: Uint8Array;
}

/**
 * Hash function interface with callable signature and properties
 * @template T - The Hash implementation type
 * @template Opts - Optional parameters type (undefined for simple hashes)
 *
 * Note: Default type parameter uses `any` due to TypeScript's limitations with
 * F-bounded polymorphism in self-referential type constraints.
 * This is a necessary compromise for the circular type dependency in Hash<T>.
 */
// deno-lint-ignore no-explicit-any
export interface CHash<T extends Hash<T> = Hash<any>, Opts = undefined>
  extends HashInfo {
  /** Output length in bytes */
  readonly outputLen: number;
  /** Block length in bytes */
  readonly blockLen: number;

  /**
   * Hash a message
   * @param msg - Message to hash
   * @param opts - Optional parameters (only for hashes that support options)
   */
  (msg: Uint8Array, opts?: Opts): Uint8Array;

  /**
   * Create a new hash instance
   * @param opts - Optional parameters (only for hashes that support options)
   */
  create(opts?: Opts): T;
}

/**
 * XOF: streaming API to read digest in chunks.
 * Same as 'squeeze' in keccak/k12 and 'seek' in blake3, but more generic name.
 * When hash used in XOF mode it is up to user to call '.destroy' afterwards, since we cannot
 * destroy state, next call can require more bytes.
 * @template T - The Hash implementation type
 */
export interface HashXOF<T extends Hash<T>> extends Hash<T> {
  /** Read 'bytes' bytes from digest stream */
  xof(bytes: number): Uint8Array;
  /** Read buf.length bytes from digest stream into buf */
  xofInto(buf: Uint8Array): Uint8Array;
}

/**
 * Hash constructor function type
 * @template T - The Hash implementation type
 * @template Opts - Optional parameters type (undefined for simple hashes)
 */
export type HasherCons<T, Opts = undefined> = Opts extends undefined ? () => T
  : (opts?: Opts) => T;

/**
 * XOF (eXtendable Output Function) interface
 * Extended hash function that can produce output of arbitrary length
 *
 * Note: Default type parameter uses `any` due to TypeScript's limitations with
 * F-bounded polymorphism in self-referential type constraints.
 * This is a necessary compromise for the circular type dependency in HashXOF<T>.
 */
// deno-lint-ignore no-explicit-any
export interface CHashXOF<T extends HashXOF<T> = HashXOF<any>, Opts = undefined>
  extends CHash<T, Opts> {
}

/** Asserts something is hash */
export function ahash(h: CHash): void {
  if (typeof h !== "function" || typeof h.create !== "function") {
    throw new Error("Hash must wrapped by utils.createHasher");
  }
  anumber(h.outputLen);
  anumber(h.blockLen);
}

export function createHasher<T extends Hash<T>, Opts = undefined>(
  hashCons: HasherCons<T, Opts>,
  info: HashInfo = {},
): CHash<T, Opts> {
  const hashFn = (msg: Uint8Array, opts?: Opts) =>
    hashCons(opts).update(msg).digest();

  const tmp = hashCons(undefined);

  const hashC = Object.assign(hashFn, {
    outputLen: tmp.outputLen,
    blockLen: tmp.blockLen,
    create: (opts?: Opts) => hashCons(opts),
    ...info,
  }) as CHash<T, Opts>;

  return Object.freeze(hashC);
}
