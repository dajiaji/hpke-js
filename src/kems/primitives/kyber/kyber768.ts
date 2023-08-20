/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import {
  sha3_256,
  sha3_512,
  shake128,
  shake256,
  // @ts-ignore: for "npm:"
} from "npm:@noble/hashes@1.3.1/sha3";

import {
  byte,
  constantTimeCompare,
  int16,
  int32,
  loadCrypto,
  uint16,
  uint32,
} from "./utils.ts";

const N = 256;
const Q = 3329;
const Q_INV = 62209;

// deno-fmt-ignore
const NTT_ZETAS = [
  2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
  2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
  732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
  1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
  107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
  430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
  1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
  418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
  1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
  478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

// deno-fmt-ignore
const NTT_ZETAS_INV = [
  1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
  1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
  1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
  1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
  3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
  1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
  1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
  2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
  829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
  3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

export class Kyber768 {
  private _api: Crypto | undefined = undefined;
  private _k = 3;
  private _du = 10;
  private _dv = 4;
  private _eta1 = 2;
  private _eta2 = 2;

  constructor() {}

  public async generateKeyPair(): Promise<[Uint8Array, Uint8Array]> {
    await this._setup();

    const rnd = new Uint8Array(64);
    (this._api as Crypto).getRandomValues(rnd);
    return this._deriveKeyPair(rnd);
  }

  public async deriveKeyPair(
    ikm: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array]> {
    await this._setup();

    if (ikm.byteLength !== 64) {
      throw new Error("ikm must be 64 bytes in length");
    }
    return this._deriveKeyPair(ikm);
  }

  public async encap(
    pk: Uint8Array,
    seed?: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array]> {
    await this._setup();

    const m = h(this._getSeed(seed));
    const [kBar, r] = g(m, h(pk));
    const ct = this._encap(pk, m, r);
    const k = kdf(kBar, h(ct));
    return [ct, k];
  }

  public async decap(sk: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
    await this._setup();

    const sk2 = sk.subarray(0, 12 * this._k * N / 8);
    const pk = sk.subarray(12 * this._k * N / 8, 24 * this._k * N / 8 + 32);
    const p = sk.subarray(24 * this._k * N / 8 + 32, 24 * this._k * N / 8 + 64);
    const z = sk.subarray(24 * this._k * N / 8 + 64, 24 * this._k * N / 8 + 96);

    const m2 = this._decap(sk2, ct);
    const [kBar2, r2] = g(m2, p);
    const ct2 = this._encap(pk, m2, r2);
    if (constantTimeCompare(ct, ct2) == 1) {
      return kdf(kBar2, h(ct));
    }
    return kdf(z, h(ct));
  }

  private async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadCrypto();
  }

  private _getSeed(seed?: Uint8Array): Uint8Array {
    if (seed == undefined) {
      const s = new Uint8Array(32);
      (this._api as Crypto).getRandomValues(s);
      return s;
    }
    if (seed.byteLength !== 32) {
      throw new Error("seed must be 32 bytes in length");
    }
    return seed;
  }

  private _deriveKeyPair(ikm: Uint8Array): [Uint8Array, Uint8Array] {
    const cpaSeed = ikm.subarray(0, 32);
    const z = ikm.subarray(32, 64);

    const cpaKeys = this._deriveCpaKeyPair(cpaSeed);

    const pk = cpaKeys[0];
    const pkh = h(pk);
    const sk = new Uint8Array(2400);
    sk.set(cpaKeys[1], 0);
    sk.set(pk, 1152);
    sk.set(pkh, 1152 + 1184);
    sk.set(z, 1152 + 1184 + 32);
    return [pk, sk];
  }

  // indcpaKeyGen generates public and private keys for the CPA-secure
  // public-key encryption scheme underlying Kyber.
  private _deriveCpaKeyPair(cpaSeed: Uint8Array): [Uint8Array, Uint8Array] {
    const seed = g(cpaSeed);
    const publicSeed = seed[0];
    const noiseSeed = seed[1];
    const a = sampleMatrix(publicSeed, this._k, false);
    const s = sampleNoise(noiseSeed, this._eta1, 0, this._k);
    const e = sampleNoise(noiseSeed, this._eta1, this._k, this._k);

    // perform number theoretic transform on secret s
    for (let i = 0; i < this._k; i++) {
      s[i] = ntt(s[i]);
      s[i] = reduce(s[i]);
      e[i] = ntt(e[i]);
    }

    // KEY COMPUTATION
    // pk = A*s + e
    const pk = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      pk[i] = polyToMont(multiply(a[i], s));
      pk[i] = add(pk[i], e[i]);
      pk[i] = reduce(pk[i]);
    }

    // PUBLIC KEY
    // turn polynomials into byte arrays
    const pubKey = new Uint8Array(1184);
    for (let i = 0; i < this._k; i++) {
      pubKey.set(polyToBytes(pk[i]), i * 384);
    }
    // append public seed
    pubKey.set(publicSeed, 1152);

    // PRIVATE KEY
    // turn polynomials into byte arrays
    const privKey = new Uint8Array(1152);
    for (let i = 0; i < this._k; i++) {
      privKey.set(polyToBytes(s[i]), i * 384);
    }
    return [pubKey, privKey];
  }

  // _encap is the encapsulation function of the CPA-secure
  // public-key encryption scheme underlying Kyber.
  private _encap(
    pk: Uint8Array,
    msg: Uint8Array,
    seed: Uint8Array,
  ): Uint8Array {
    const tHat = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      tHat[i] = polyFromBytes(pk.subarray(i * 384, (i + 1) * 384));
    }
    const rho = pk.subarray(1152);
    const a = sampleMatrix(rho, this._k, true);
    const r = sampleNoise(seed, this._eta1, 0, this._k);
    const e1 = sampleNoise(seed, this._eta1, this._k, this._k);
    const e2 = sampleNoise(seed, this._eta2, this._k * 2, 1)[0];

    // perform number theoretic transform on random vector r
    for (let i = 0; i < this._k; i++) {
      r[i] = ntt(r[i]);
      r[i] = reduce(r[i]);
    }

    // u = A*r + e1
    const u = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      u[i] = multiply(a[i], r);
      u[i] = nttInverse(u[i]);
      u[i] = add(u[i], e1[i]);
      u[i] = reduce(u[i]);
    }

    // v = tHat*r + e2 + m
    const m = polyFromMsg(msg);
    let v = multiply(tHat, r);
    v = nttInverse(v);
    v = add(v, e2);
    v = add(v, m);
    v = reduce(v);

    // compress
    const ret = new Uint8Array(960 + 128);
    this._compress1(ret.subarray(0, 960), u);
    this._compress2(ret.subarray(960), v);
    return ret;
  }

  // indcpaDecrypt is the decryption function of the CPA-secure
  // public-key encryption scheme underlying Kyber.
  private _decap(sk: Uint8Array, ct: Uint8Array): Uint8Array {
    // extract ciphertext
    const u = this._decompress1(ct.subarray(0, 960));
    const v = this._decompress2(ct.subarray(960, 1088));

    const privateKeyPolyvec = this._polyvecFromBytes(sk);

    for (let i = 0; i < this._k; i++) {
      u[i] = ntt(u[i]);
    }

    let mp = multiply(privateKeyPolyvec, u);
    mp = nttInverse(mp);
    mp = subtract(v, mp);
    mp = reduce(mp);
    return polyToMsg(mp);
  }

  // polyvecFromBytes deserializes a vector of polynomials.
  private _polyvecFromBytes(a: Uint8Array): Array<Array<number>> {
    const r = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Array<number>(384);
    }
    for (let i = 0; i < this._k; i++) {
      r[i] = polyFromBytes(a.subarray(i * 384, (i + 1) * 384));
    }
    return r;
  }

  // compress1 lossily compresses and serializes a vector of polynomials.
  private _compress1(r: Uint8Array, u: Array<Array<number>>): Uint8Array {
    // const r = new Uint8Array(960);
    const t = new Array<number>(4);
    for (let rr = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        for (let k = 0; k < 4; k++) {
          // parse {0,...,3328} to {0,...,1023}
          t[k] = (((u[i][4 * j + k] << 10) + Q / 2) / Q) &
            0b1111111111;
        }
        // converts 4 12-bit coefficients {0,...,3328} to 5 8-bit bytes {0,...,255}
        // 48 bits down to 40 bits per block
        r[rr + 0] = byte(t[0] >> 0);
        r[rr + 1] = byte((t[0] >> 8) | (t[1] << 2));
        r[rr + 2] = byte((t[1] >> 6) | (t[2] << 4));
        r[rr + 3] = byte((t[2] >> 4) | (t[3] << 6));
        r[rr + 4] = byte(t[3] >> 2);
        rr = rr + 5;
      }
    }
    return r;
  }

  // compress2 lossily compresses and subsequently serializes a polynomial.
  private _compress2(r: Uint8Array, v: Array<number>): Uint8Array {
    // const r = new Uint8Array(128);
    const t = new Uint8Array(8);
    for (let rr = 0, i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        t[j] = byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 0b1111;
      }
      r[rr + 0] = t[0] | (t[1] << 4);
      r[rr + 1] = t[2] | (t[3] << 4);
      r[rr + 2] = t[4] | (t[5] << 4);
      r[rr + 3] = t[6] | (t[7] << 4);
      rr = rr + 4;
    }
    return r;
  }

  // decompress1 de-serializes and decompresses a vector of polynomials and
  // represents the approximate inverse of compress1. Since compression is lossy,
  // the results of decompression will may not match the original vector of polynomials.
  private _decompress1(a: Uint8Array): Array<Array<number>> {
    const r = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Array<number>(384);
    }
    const t = new Array<number>(4);
    for (let aa = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
        t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
        t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
        t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
        aa = aa + 5;
        for (let k = 0; k < 4; k++) {
          r[i][4 * j + k] = int16(
            (((uint32(t[k] & 0x3FF) >>> 0) * (uint32(Q) >>> 0) >>> 0) +
                  512) >> 10 >>> 0,
          );
        }
      }
    }
    return r;
  }

  // decompress2 de-serializes and subsequently decompresses a polynomial,
  // representing the approximate inverse of compress2.
  // Note that compression is lossy, and thus decompression will not match the
  // original input.
  private _decompress2(a: Uint8Array): Array<number> {
    const r = new Array<number>(384);
    let aa = 0;
    for (let i = 0; i < N / 2; i++) {
      r[2 * i + 0] = int16(((uint16(a[aa] & 15) * uint16(Q)) + 8) >> 4);
      r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(Q)) + 8) >> 4);
      aa = aa + 1;
    }
    return r;
  }
}

function g(a: Uint8Array, b?: Uint8Array): [Uint8Array, Uint8Array] {
  const hash = sha3_512.create().update(a);
  if (b !== undefined) {
    hash.update(b);
  }
  const res = hash.digest();
  return [res.subarray(0, 32), res.subarray(32, 64)];
}

function h(msg: Uint8Array): Uint8Array {
  return sha3_256.create().update(msg).digest();
}

function kdf(a: Uint8Array, b?: Uint8Array): Uint8Array {
  const hash = shake256.create({ dkLen: 32 }).update(a);
  if (b !== undefined) {
    hash.update(b);
  }
  return hash.digest();
}

function xof(seed: Uint8Array, transpose: Uint8Array): Uint8Array {
  return shake128.create({ dkLen: 672 }).update(seed).update(transpose)
    .digest();
}

// generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
function sampleMatrix(
  seed: Uint8Array,
  paramsK: number,
  transposed: boolean,
): Array<Array<Array<number>>> {
  const a = new Array<Array<Array<number>>>(3);
  const transpose = new Uint8Array(2);

  for (let ctr = 0, i = 0; i < paramsK; i++) {
    a[i] = new Array<Array<number>>(paramsK);

    for (let j = 0; j < paramsK; j++) {
      // set if transposed matrix or not
      if (transposed) {
        transpose[0] = i;
        transpose[1] = j;
      } else {
        transpose[0] = j;
        transpose[1] = i;
      }
      const output = xof(seed, transpose);

      // run rejection sampling on the output from above
      const result = indcpaRejUniform(output.subarray(0, 504), 504, N);
      a[i][j] = result[0]; // the result here is an NTT-representation
      ctr = result[1]; // keeps track of index of output array from sampling function

      while (ctr < N) { // if the polynomial hasnt been filled yet with mod q entries
        const outputn = output.subarray(504, 672); // take last 168 bytes of byte array from xof
        const result1 = indcpaRejUniform(outputn, 168, N - ctr); // run sampling function again
        const missing = result1[0]; // here is additional mod q polynomial coefficients
        const ctrn = result1[1]; // how many coefficients were accepted and are in the output
        // starting at last position of output array from first sampling function until 256 is reached
        for (let k = ctr; k < N; k++) {
          a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
        }
        ctr = ctr + ctrn; // update index
      }
    }
  }
  return a;
}

// polyToBytes serializes a polynomial into an array of bytes.
function polyToBytes(a: Array<number>): Uint8Array {
  let t0 = 0;
  let t1 = 0;
  const r = new Uint8Array(384);
  const a2 = subtractQ(a); // Returns: a - q if a >= q, else a (each coefficient of the polynomial)
  // for 0-127
  for (let i = 0; i < N / 2; i++) {
    // get two coefficient entries in the polynomial
    t0 = uint16(a2[2 * i]);
    t1 = uint16(a2[2 * i + 1]);

    // convert the 2 coefficient into 3 bytes
    r[3 * i + 0] = byte(t0 >> 0); // byte() does mod 256 of the input (output value 0-255)
    r[3 * i + 1] = byte(t0 >> 8) | byte(t1 << 4);
    r[3 * i + 2] = byte(t1 >> 4);
  }
  return r;
}

// polyFromBytes de-serialises an array of bytes into a polynomial,
// and represents the inverse of polyToBytes.
function polyFromBytes(a: Uint8Array): Array<number> {
  const r = new Array<number>(384).fill(0);
  for (let i = 0; i < N / 2; i++) {
    r[2 * i] = int16(
      ((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF,
    );
    r[2 * i + 1] = int16(
      ((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF,
    );
  }
  return r;
}

// polyToMsg converts a polynomial to a 32-byte message
// and represents the inverse of polyFromMsg.
function polyToMsg(a: Array<number>): Uint8Array {
  const msg = new Uint8Array(32);
  let t;
  const a2 = subtractQ(a);
  for (let i = 0; i < N / 8; i++) {
    msg[i] = 0;
    for (let j = 0; j < 8; j++) {
      t = (((uint16(a2[8 * i + j]) << 1) + uint16(Q / 2)) /
        uint16(Q)) & 1;
      msg[i] |= byte(t << j);
    }
  }
  return msg;
}

// polyFromMsg converts a 32-byte message to a polynomial.
function polyFromMsg(msg: Uint8Array): Array<number> {
  const r = new Array<number>(384).fill(0); // each element is int16 (0-65535)
  let mask; // int16
  for (let i = 0; i < N / 8; i++) {
    for (let j = 0; j < 8; j++) {
      mask = -1 * int16((msg[i] >> j) & 1);
      r[8 * i + j] = mask & int16((Q + 1) / 2);
    }
  }
  return r;
}

// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
function indcpaRejUniform(
  buf: Uint8Array,
  bufl: number,
  len: number,
): [Array<number>, number] {
  const r = new Array<number>(384).fill(0);
  let ctr = 0;
  let val0, val1; // d1, d2 in kyber documentation

  for (let pos = 0; ctr < len && pos + 3 <= bufl;) {
    // compute d1 and d2
    val0 = (uint16((buf[pos]) >> 0) | (uint16(buf[pos + 1]) << 8)) & 0xFFF;
    val1 = (uint16((buf[pos + 1]) >> 4) | (uint16(buf[pos + 2]) << 4)) & 0xFFF;

    // increment input buffer index by 3
    pos = pos + 3;

    // if d1 is less than 3329
    if (val0 < Q) {
      // assign to d1
      r[ctr] = val0;
      // increment position of output array
      ctr = ctr + 1;
    }
    if (ctr < len && val1 < Q) {
      r[ctr] = val1;
      ctr = ctr + 1;
    }
  }
  return [r, ctr];
}

// sample samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution with parameter PARAMS_ETA = 2.
function sampleNoise(
  sigma: Uint8Array,
  eta: number,
  offset: number,
  paramsK: number,
): Array<Array<number>> {
  const r = new Array<Array<number>>(paramsK);
  for (let i = 0; i < paramsK; i++) {
    r[i] = byteopsCbd(prf(sigma, offset), eta);
    offset++;
  }
  return r;
}

// prf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
function prf(seed: Uint8Array, nonce: number): Uint8Array {
  return shake256.create({ dkLen: 2000 }).update(seed).update(
    new Uint8Array([nonce]),
  ).digest();
}

// byteopsCbd computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter PARAMS_ETA,
// given an array of uniformly random bytes.
function byteopsCbd(buf: Uint8Array, eta: number): Array<number> {
  let t, d;
  let a, b;
  const r = new Array<number>(384).fill(0);
  for (let i = 0; i < N / 8; i++) {
    t = byteopsLoad32(buf.subarray(4 * i, buf.length)) >>> 0;
    d = (t & 0x55555555) >>> 0;
    d = d + ((((t >> 1) >>> 0) & 0x55555555) >>> 0) >>> 0;
    for (let j = 0; j < 8; j++) {
      a = int16((((d >> (4 * j + 0)) >>> 0) & 0x3) >>> 0);
      b = int16((((d >> (4 * j + eta)) >>> 0) & 0x3) >>> 0);
      r[8 * i + j] = a - b;
    }
  }
  return r;
}

// byteopsLoad32 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad32(x: Uint8Array): number {
  let r = uint32(x[0]);
  r = ((r | (uint32(x[1]) << 8)) >>> 0) >>> 0;
  r = ((r | (uint32(x[2]) << 16)) >>> 0) >>> 0;
  r = ((r | (uint32(x[3]) << 24)) >>> 0) >>> 0;
  return uint32(r);
}

// ntt performs an inplace number-theoretic transform (NTT) in `Rq`.
// The input is in standard order, the output is in bit-reversed order.
function ntt(r: Array<number>): Array<number> {
  // 128, 64, 32, 16, 8, 4, 2
  for (let j = 0, k = 1, l = 128; l >= 2; l >>= 1) {
    // 0,
    for (let start = 0; start < 256; start = j + l) {
      const zeta = NTT_ZETAS[k];
      k = k + 1;
      // for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
      for (j = start; j < start + l; j++) {
        // compute the modular multiplication of the zeta and each element in the subsection
        const t = nttFqMul(zeta, r[j + l]); // t is mod q
        // overwrite each element in the subsection as the opposite subsection element minus t
        r[j + l] = r[j] - t;
        // add t back again to the opposite subsection
        r[j] = r[j] + t;
      }
    }
  }
  return r;
}

// nttFqMul performs multiplication followed by Montgomery reduction
// and returns a 16-bit integer congruent to `a*b*R^{-1} mod Q`.
function nttFqMul(a: number, b: number): number {
  return byteopsMontgomeryReduce(a * b);
}

// reduce applies Barrett reduction to all coefficients of a polynomial.
function reduce(r: Array<number>): Array<number> {
  for (let i = 0; i < N; i++) {
    r[i] = barrett(r[i]);
  }
  return r;
}

// barrett computes a Barrett reduction; given
// a integer `a`, returns a integer congruent to
// `a mod Q` in {0,...,Q}.
function barrett(a: number): number {
  const v = ((1 << 24) + Q / 2) / Q;
  let t = v * a >> 24;
  t = t * Q;
  return a - t;
}

// byteopsMontgomeryReduce computes a Montgomery reduction; given
// a 32-bit integer `a`, returns `a * R^-1 mod Q` where `R=2^16`.
function byteopsMontgomeryReduce(a: number): number {
  const u = int16(int32(a) * Q_INV);
  let t = u * Q;
  t = a - t;
  t >>= 16;
  return int16(t);
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
function polyToMont(r: Array<number>): Array<number> {
  // let f = int16(((uint64(1) << 32) >>> 0) % uint64(Q));
  const f = 1353; // if Q changes then this needs to be updated
  for (let i = 0; i < N; i++) {
    r[i] = byteopsMontgomeryReduce(int32(r[i]) * int32(f));
  }
  return r;
}

// pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
function multiply(
  a: Array<Array<number>>,
  b: Array<Array<number>>,
): Array<number> {
  let r = polyBaseMulMontgomery(a[0], b[0]);
  let t;
  for (let i = 1; i < a.length; i++) {
    t = polyBaseMulMontgomery(a[i], b[i]);
    r = add(r, t);
  }
  return reduce(r);
}

// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.
function polyBaseMulMontgomery(
  a: Array<number>,
  b: Array<number>,
): Array<number> {
  let rx, ry;
  for (let i = 0; i < N / 4; i++) {
    rx = nttBaseMul(
      a[4 * i + 0],
      a[4 * i + 1],
      b[4 * i + 0],
      b[4 * i + 1],
      NTT_ZETAS[64 + i],
    );
    ry = nttBaseMul(
      a[4 * i + 2],
      a[4 * i + 3],
      b[4 * i + 2],
      b[4 * i + 3],
      -NTT_ZETAS[64 + i],
    );
    a[4 * i + 0] = rx[0];
    a[4 * i + 1] = rx[1];
    a[4 * i + 2] = ry[0];
    a[4 * i + 3] = ry[1];
  }
  return a;
}

// nttBaseMul performs the multiplication of polynomials
// in `Zq[X]/(X^2-zeta)`. Used for multiplication of elements
// in `Rq` in the number-theoretic transformation domain.
function nttBaseMul(
  a0: number,
  a1: number,
  b0: number,
  b1: number,
  zeta: number,
): Array<number> {
  const r = new Array<number>(2);
  r[0] = nttFqMul(a1, b1);
  r[0] = nttFqMul(r[0], zeta);
  r[0] = r[0] + nttFqMul(a0, b0);
  r[1] = nttFqMul(a0, b1);
  r[1] = r[1] + nttFqMul(a1, b0);
  return r;
}

// adds two polynomials.
function add(a: Array<number>, b: Array<number>): Array<number> {
  const c = new Array<number>(384);
  for (let i = 0; i < N; i++) {
    c[i] = a[i] + b[i];
  }
  return c;
}

// subtracts two polynomials.
function subtract(a: Array<number>, b: Array<number>): Array<number> {
  for (let i = 0; i < N; i++) {
    a[i] = a[i] - b[i];
  }
  return a;
}

// nttInverse performs an inplace inverse number-theoretic transform (NTT)
// in `Rq` and multiplication by Montgomery factor 2^16.
// The input is in bit-reversed order, the output is in standard order.
function nttInverse(r: Array<number>): Array<number> {
  let j = 0;
  for (let k = 0, l = 2; l <= 128; l <<= 1) {
    for (let start = 0; start < 256; start = j + l) {
      const zeta = NTT_ZETAS_INV[k];
      k = k + 1;
      for (j = start; j < start + l; j++) {
        const t = r[j];
        r[j] = barrett(t + r[j + l]);
        r[j + l] = t - r[j + l];
        r[j + l] = nttFqMul(zeta, r[j + l]);
      }
    }
  }
  for (j = 0; j < 256; j++) {
    r[j] = nttFqMul(r[j], NTT_ZETAS_INV[127]);
  }
  return r;
}

// subtractQ applies the conditional subtraction of q to each coefficient of a polynomial.
// if a is 3329 then convert to 0
// Returns:     a - q if a >= q, else a
function subtractQ(r: Array<number>): Array<number> {
  for (let i = 0; i < N; i++) {
    r[i] = r[i] - Q; // should result in a negative integer
    // push left most signed bit to right most position
    // javascript does bitwise operations in signed 32 bit
    // add q back again if left most bit was 0 (positive number)
    r[i] = r[i] + ((r[i] >> 31) & Q);
  }
  return r;
}
