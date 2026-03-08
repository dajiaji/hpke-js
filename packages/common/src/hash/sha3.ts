/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/src/sha3.ts
 */

/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out [FIPS-202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
 * [Website](https://keccak.team/keccak.html),
 * [the differences between SHA-3 and Keccak](https://crypto.stackexchange.com/questions/15727/what-are-the-key-differences-between-the-draft-sha-3-standard-and-the-keccak-sub).
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */
import { rotlBH, rotlBL, rotlSH, rotlSL, split } from "./u64.ts";
import {
  abytes,
  aexists,
  anumber,
  aoutput,
  clean,
  oidNist,
  swap32IfBE,
  u32,
} from "../utils/noble.ts";
import {
  type CHash,
  type CHashXOF,
  createHasher,
  type Hash,
  type HashInfo,
  type HashXOF,
} from "./hash.ts";

// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n = 0n;
const _1n = 1n;
const _2n = 2n;
const _7n = 7n;
const _256n = 256n;
const _0x71n = 0x71n;
const SHA3_PI: number[] = [];
const SHA3_ROTL: number[] = [];
const _SHA3_IOTA: bigint[] = []; // no pure annotation: var is always used
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
  // Pi
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  // Rotational
  SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
  // Iota
  let t = _0n;
  for (let j = 0; j < 7; j++) {
    R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
    if (R & _2n) t ^= _1n << ((_1n << BigInt(j)) - _1n);
  }
  _SHA3_IOTA.push(t);
}
const IOTAS = split(_SHA3_IOTA, true);
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];

// Left rotation (without 0, 32, 64)
const rotlH = (
  h: number,
  l: number,
  s: number,
) => (s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s));
const rotlL = (
  h: number,
  l: number,
  s: number,
) => (s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s));

/** `keccakf1600` internal function, additionally allows to adjust round count. */
export function keccakP(
  s: Uint32Array,
  rounds: number = 24,
  B?: Uint32Array,
): void {
  if (!B) B = new Uint32Array(10);
  // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
  for (let round = 24 - rounds; round < 24; round++) {
    // Theta θ
    for (let x = 0; x < 10; x++) {
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    }
    // for (let x = 0; x < 10; x += 2) {
    //   const idx1 = (x + 8) % 10;
    //   const idx0 = (x + 2) % 10;
    //   const B0 = B[idx0];
    //   const B1 = B[idx0 + 1];
    //   const Th = rotlH(B0, B1, 1) ^ B[idx1];
    //   const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
    //   for (let y = 0; y < 50; y += 10) {
    //     s[x + y] ^= Th;
    //     s[x + y + 1] ^= Tl;
    //   }
    // }
    { // x=0: idx0=2, idx1=8
      const Th = rotlH(B[2], B[3], 1) ^ B[8];
      const Tl = rotlL(B[2], B[3], 1) ^ B[9];
      s[0] ^= Th;
      s[1] ^= Tl;
      s[10] ^= Th;
      s[11] ^= Tl;
      s[20] ^= Th;
      s[21] ^= Tl;
      s[30] ^= Th;
      s[31] ^= Tl;
      s[40] ^= Th;
      s[41] ^= Tl;
    }
    { // x=2: idx0=4, idx1=0
      const Th = rotlH(B[4], B[5], 1) ^ B[0];
      const Tl = rotlL(B[4], B[5], 1) ^ B[1];
      s[2] ^= Th;
      s[3] ^= Tl;
      s[12] ^= Th;
      s[13] ^= Tl;
      s[22] ^= Th;
      s[23] ^= Tl;
      s[32] ^= Th;
      s[33] ^= Tl;
      s[42] ^= Th;
      s[43] ^= Tl;
    }
    { // x=4: idx0=6, idx1=2
      const Th = rotlH(B[6], B[7], 1) ^ B[2];
      const Tl = rotlL(B[6], B[7], 1) ^ B[3];
      s[4] ^= Th;
      s[5] ^= Tl;
      s[14] ^= Th;
      s[15] ^= Tl;
      s[24] ^= Th;
      s[25] ^= Tl;
      s[34] ^= Th;
      s[35] ^= Tl;
      s[44] ^= Th;
      s[45] ^= Tl;
    }
    { // x=6: idx0=8, idx1=4
      const Th = rotlH(B[8], B[9], 1) ^ B[4];
      const Tl = rotlL(B[8], B[9], 1) ^ B[5];
      s[6] ^= Th;
      s[7] ^= Tl;
      s[16] ^= Th;
      s[17] ^= Tl;
      s[26] ^= Th;
      s[27] ^= Tl;
      s[36] ^= Th;
      s[37] ^= Tl;
      s[46] ^= Th;
      s[47] ^= Tl;
    }
    { // x=8: idx0=0, idx1=6
      const Th = rotlH(B[0], B[1], 1) ^ B[6];
      const Tl = rotlL(B[0], B[1], 1) ^ B[7];
      s[8] ^= Th;
      s[9] ^= Tl;
      s[18] ^= Th;
      s[19] ^= Tl;
      s[28] ^= Th;
      s[29] ^= Tl;
      s[38] ^= Th;
      s[39] ^= Tl;
      s[48] ^= Th;
      s[49] ^= Tl;
    }
    // Rho (ρ) and Pi (π) — fully unrolled
    let curH = s[2];
    let curL = s[3];
    // for (let t = 0; t < 24; t++) {
    //   const shift = SHA3_ROTL[t];
    //   const Th = rotlH(curH, curL, shift);
    //   const Tl = rotlL(curH, curL, shift);
    //   const PI = SHA3_PI[t];
    //   curH = s[PI];
    //   curL = s[PI + 1];
    //   s[PI] = Th;
    //   s[PI + 1] = Tl;
    // }
    let Th, Tl;
    // t=0: shift=1(S), PI=20
    Th = rotlSH(curH, curL, 1);
    Tl = rotlSL(curH, curL, 1);
    curH = s[20];
    curL = s[21];
    s[20] = Th;
    s[21] = Tl;
    // t=1: shift=3(S), PI=14
    Th = rotlSH(curH, curL, 3);
    Tl = rotlSL(curH, curL, 3);
    curH = s[14];
    curL = s[15];
    s[14] = Th;
    s[15] = Tl;
    // t=2: shift=6(S), PI=22
    Th = rotlSH(curH, curL, 6);
    Tl = rotlSL(curH, curL, 6);
    curH = s[22];
    curL = s[23];
    s[22] = Th;
    s[23] = Tl;
    // t=3: shift=10(S), PI=34
    Th = rotlSH(curH, curL, 10);
    Tl = rotlSL(curH, curL, 10);
    curH = s[34];
    curL = s[35];
    s[34] = Th;
    s[35] = Tl;
    // t=4: shift=15(S), PI=36
    Th = rotlSH(curH, curL, 15);
    Tl = rotlSL(curH, curL, 15);
    curH = s[36];
    curL = s[37];
    s[36] = Th;
    s[37] = Tl;
    // t=5: shift=21(S), PI=6
    Th = rotlSH(curH, curL, 21);
    Tl = rotlSL(curH, curL, 21);
    curH = s[6];
    curL = s[7];
    s[6] = Th;
    s[7] = Tl;
    // t=6: shift=28(S), PI=10
    Th = rotlSH(curH, curL, 28);
    Tl = rotlSL(curH, curL, 28);
    curH = s[10];
    curL = s[11];
    s[10] = Th;
    s[11] = Tl;
    // t=7: shift=36(B), PI=32
    Th = rotlBH(curH, curL, 36);
    Tl = rotlBL(curH, curL, 36);
    curH = s[32];
    curL = s[33];
    s[32] = Th;
    s[33] = Tl;
    // t=8: shift=45(B), PI=16
    Th = rotlBH(curH, curL, 45);
    Tl = rotlBL(curH, curL, 45);
    curH = s[16];
    curL = s[17];
    s[16] = Th;
    s[17] = Tl;
    // t=9: shift=55(B), PI=42
    Th = rotlBH(curH, curL, 55);
    Tl = rotlBL(curH, curL, 55);
    curH = s[42];
    curL = s[43];
    s[42] = Th;
    s[43] = Tl;
    // t=10: shift=2(S), PI=48
    Th = rotlSH(curH, curL, 2);
    Tl = rotlSL(curH, curL, 2);
    curH = s[48];
    curL = s[49];
    s[48] = Th;
    s[49] = Tl;
    // t=11: shift=14(S), PI=8
    Th = rotlSH(curH, curL, 14);
    Tl = rotlSL(curH, curL, 14);
    curH = s[8];
    curL = s[9];
    s[8] = Th;
    s[9] = Tl;
    // t=12: shift=27(S), PI=30
    Th = rotlSH(curH, curL, 27);
    Tl = rotlSL(curH, curL, 27);
    curH = s[30];
    curL = s[31];
    s[30] = Th;
    s[31] = Tl;
    // t=13: shift=41(B), PI=46
    Th = rotlBH(curH, curL, 41);
    Tl = rotlBL(curH, curL, 41);
    curH = s[46];
    curL = s[47];
    s[46] = Th;
    s[47] = Tl;
    // t=14: shift=56(B), PI=38
    Th = rotlBH(curH, curL, 56);
    Tl = rotlBL(curH, curL, 56);
    curH = s[38];
    curL = s[39];
    s[38] = Th;
    s[39] = Tl;
    // t=15: shift=8(S), PI=26
    Th = rotlSH(curH, curL, 8);
    Tl = rotlSL(curH, curL, 8);
    curH = s[26];
    curL = s[27];
    s[26] = Th;
    s[27] = Tl;
    // t=16: shift=25(S), PI=24
    Th = rotlSH(curH, curL, 25);
    Tl = rotlSL(curH, curL, 25);
    curH = s[24];
    curL = s[25];
    s[24] = Th;
    s[25] = Tl;
    // t=17: shift=43(B), PI=4
    Th = rotlBH(curH, curL, 43);
    Tl = rotlBL(curH, curL, 43);
    curH = s[4];
    curL = s[5];
    s[4] = Th;
    s[5] = Tl;
    // t=18: shift=62(B), PI=40
    Th = rotlBH(curH, curL, 62);
    Tl = rotlBL(curH, curL, 62);
    curH = s[40];
    curL = s[41];
    s[40] = Th;
    s[41] = Tl;
    // t=19: shift=18(S), PI=28
    Th = rotlSH(curH, curL, 18);
    Tl = rotlSL(curH, curL, 18);
    curH = s[28];
    curL = s[29];
    s[28] = Th;
    s[29] = Tl;
    // t=20: shift=39(B), PI=44
    Th = rotlBH(curH, curL, 39);
    Tl = rotlBL(curH, curL, 39);
    curH = s[44];
    curL = s[45];
    s[44] = Th;
    s[45] = Tl;
    // t=21: shift=61(B), PI=18
    Th = rotlBH(curH, curL, 61);
    Tl = rotlBL(curH, curL, 61);
    curH = s[18];
    curL = s[19];
    s[18] = Th;
    s[19] = Tl;
    // t=22: shift=20(S), PI=12
    Th = rotlSH(curH, curL, 20);
    Tl = rotlSL(curH, curL, 20);
    curH = s[12];
    curL = s[13];
    s[12] = Th;
    s[13] = Tl;
    // t=23: shift=44(B), PI=2
    Th = rotlBH(curH, curL, 44);
    Tl = rotlBL(curH, curL, 44);
    s[2] = Th;
    s[3] = Tl;
    // Chi (χ)
    for (let y = 0; y < 50; y += 10) {
      B[0] = s[y];
      B[1] = s[y + 1];
      B[2] = s[y + 2];
      B[3] = s[y + 3];
      B[4] = s[y + 4];
      B[5] = s[y + 5];
      B[6] = s[y + 6];
      B[7] = s[y + 7];
      B[8] = s[y + 8];
      B[9] = s[y + 9];
      s[y + 0] ^= ~B[2] & B[4];
      s[y + 1] ^= ~B[3] & B[5];
      s[y + 2] ^= ~B[4] & B[6];
      s[y + 3] ^= ~B[5] & B[7];
      s[y + 4] ^= ~B[6] & B[8];
      s[y + 5] ^= ~B[7] & B[9];
      s[y + 6] ^= ~B[8] & B[0];
      s[y + 7] ^= ~B[9] & B[1];
      s[y + 8] ^= ~B[0] & B[2];
      s[y + 9] ^= ~B[1] & B[3];
    }
    // Iota (ι)
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
}

/** Keccak sponge function. */
export class Keccak implements Hash<Keccak>, HashXOF<Keccak> {
  protected state: Uint8Array;
  protected pos = 0;
  protected posOut = 0;
  protected finished = false;
  protected state32: Uint32Array;
  protected destroyed = false;
  private _B = new Uint32Array(10);

  public blockLen: number;
  public suffix: number;
  public outputLen: number;
  protected enableXOF = false;
  protected rounds: number;

  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(
    blockLen: number,
    suffix: number,
    outputLen: number,
    enableXOF = false,
    rounds: number = 24,
  ) {
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    // Can be passed from user as dkLen
    anumber(outputLen, "outputLen");
    // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
    // 0 < blockLen < 200
    if (!(0 < blockLen && blockLen < 200)) {
      throw new Error("only keccak-f1600 function is supported");
    }
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone(): Keccak {
    return this._cloneInto();
  }
  /** Resets instance to initial (empty) state for reuse. */
  reset(): void {
    this.state.fill(0);
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
  }
  protected keccak(): void {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds, this._B);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data: Uint8Array): this {
    aexists(this);
    abytes(data);
    return this.updateUnsafe(data);
  }
  /** Like update(), but skips validation. Caller must ensure valid state and input. */
  updateUnsafe(data: Uint8Array): this {
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len;) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++) state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen) this.keccak();
    }
    return this;
  }
  protected finish(): void {
    if (this.finished) return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    // Do the padding
    state[pos] ^= suffix;
    if ((suffix & 0x80) !== 0 && pos === blockLen - 1) this.keccak();
    state[blockLen - 1] ^= 0x80;
    this.keccak();
  }
  protected writeInto(out: Uint8Array): Uint8Array {
    aexists(this, false);
    abytes(out);
    return this.writeIntoUnsafe(out);
  }
  /** Like writeInto(), but skips validation. Caller must ensure valid state and output. */
  writeIntoUnsafe(out: Uint8Array): Uint8Array {
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len;) {
      if (this.posOut >= blockLen) this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out: Uint8Array): Uint8Array {
    // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
    if (!this.enableXOF) {
      throw new Error("XOF is not possible for this instance");
    }
    return this.writeInto(out);
  }
  xof(bytes: number): Uint8Array {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out: Uint8Array): Uint8Array {
    aoutput(out, this);
    if (this.finished) throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest(): Uint8Array {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy(): void {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to?: Keccak): Keccak {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    // Suffix can change in cSHAKE
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}

const genKeccak = (
  suffix: number,
  blockLen: number,
  outputLen: number,
  info: HashInfo = {},
) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);

// /** SHA3-224 hash function. */
// export const sha3_224: CHash = /* @__PURE__ */ genKeccak(
//   0x06,
//   144,
//   28,
//   /* @__PURE__ */ oidNist(0x07),
// );

/** SHA3-256 hash function. Different from keccak-256. */
export const sha3_256: CHash = /* @__PURE__ */ genKeccak(
  0x06,
  136,
  32,
  /* @__PURE__ */ oidNist(0x08),
);

/** SHA3-384 hash function. */
export const sha3_384: CHash = /* @__PURE__ */ genKeccak(
  0x06,
  104,
  48,
  /* @__PURE__ */ oidNist(0x09),
);

/** SHA3-512 hash function. */
export const sha3_512: CHash = /* @__PURE__ */ genKeccak(
  0x06,
  72,
  64,
  /* @__PURE__ */ oidNist(0x0a),
);

/** keccak-224 hash function. */
export const keccak_224: CHash = /* @__PURE__ */ genKeccak(0x01, 144, 28);
/** keccak-256 hash function. Different from SHA3-256. */
export const keccak_256: CHash = /* @__PURE__ */ genKeccak(0x01, 136, 32);
/** keccak-384 hash function. */
export const keccak_384: CHash = /* @__PURE__ */ genKeccak(0x01, 104, 48);
/** keccak-512 hash function. */
export const keccak_512: CHash = /* @__PURE__ */ genKeccak(0x01, 72, 64);

export type ShakeOpts = { dkLen?: number };

const genShake = (
  suffix: number,
  blockLen: number,
  outputLen: number,
  info: HashInfo = {},
) =>
  createHasher<Keccak, ShakeOpts>(
    (opts: ShakeOpts = {}) =>
      new Keccak(
        blockLen,
        suffix,
        opts.dkLen === undefined ? outputLen : opts.dkLen,
        true,
      ),
    info,
  );

/** SHAKE128 XOF with 128-bit security. */
export const shake128: CHashXOF<Keccak, ShakeOpts> =
  /* @__PURE__ */
  genShake(0x1f, 168, 16, /* @__PURE__ */ oidNist(0x0b));
/** SHAKE256 XOF with 256-bit security. */
export const shake256: CHashXOF<Keccak, ShakeOpts> =
  /* @__PURE__ */
  genShake(0x1f, 136, 32, /* @__PURE__ */ oidNist(0x0c));

// /** SHAKE128 XOF with 256-bit output (NIST version). */
// export const shake128_32: CHashXOF<Keccak, ShakeOpts> =
//   /* @__PURE__ */
//   genShake(0x1f, 168, 32, /* @__PURE__ */ oidNist(0x0b));
// /** SHAKE256 XOF with 512-bit output (NIST version). */
// export const shake256_64: CHashXOF<Keccak, ShakeOpts> =
//   /* @__PURE__ */
//   genShake(0x1f, 136, 64, /* @__PURE__ */ oidNist(0x0c));
