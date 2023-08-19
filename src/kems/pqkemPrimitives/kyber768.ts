import {
  sha3_256,
  sha3_512,
  shake128,
  shake256,
  // @ts-ignore: for "npm:"
} from "npm:@noble/hashes@1.3.1/sha3";

import { concat, isBrowser, isCloudflareWorkers } from "../../utils/misc.ts";

// deno-fmt-ignore
const nttZetas = [
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
const nttZetasInv = [
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

const paramsK = 3;
const paramsN = 256;
const paramsQ = 3329;
const paramsQinv = 62209;
const paramsETA = 2;

export class Kyber768 {
  private _api: Crypto | undefined = undefined;

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
    ikm?: Uint8Array,
  ): Promise<[Uint8Array, Uint8Array]> {
    await this._setup();

    // random 32 bytes m
    let m: Uint8Array;
    if (ikm === undefined) {
      m = new Uint8Array(32);
      (this._api as Crypto).getRandomValues(m);
    } else {
      if (ikm.byteLength !== 32) {
        throw new Error("ikm must be 32 bytes in length");
      }
      m = ikm;
    }
    const mh = sha3_256.create().update(m).digest();
    const pkh = sha3_256.create().update(pk).digest();
    const kr = sha3_512.create().update(mh).update(pkh).digest();
    const kr1 = kr.subarray(0, 32);
    const kr2 = kr.subarray(32, 64);
    const c = this._encap(pk, mh, kr2);
    const ch = sha3_256.create().update(c).digest();
    const ss = shake256.create({}).update(kr1).update(ch).digest();
    return [c, ss];
  }

  public async decap(
    c: Uint8Array,
    privateKey: Uint8Array,
  ): Promise<Uint8Array> {
    await this._setup();

    // extract sk, pk, pkh and z
    const sk = privateKey.subarray(0, 1152);
    const pk = privateKey.subarray(1152, 2336);
    const pkh = privateKey.subarray(2336, 2368);
    const z = privateKey.subarray(2368, 2400);

    // IND-CPA decrypt
    const m = this._decap(c, sk);
    const kr = sha3_512.create().update(m).update(pkh).digest();
    const kr1 = kr.subarray(0, 32);
    const kr2 = kr.subarray(32, 64);

    // IND-CPA encrypt
    const cmp = this._encap(pk, m, kr2);

    // compare c and cmp
    const validated = compareArray(c, cmp);

    // hash c with SHA3-256
    const ch = sha3_256.create().update(c).digest();

    let ss: Uint8Array;
    if (validated) {
      ss = shake256.create({}).update(kr1).update(ch).digest();
    } else {
      ss = shake256.create({}).update(z).update(ch).digest();
    }
    return ss;
  }

  private _deriveKeyPair(ikm: Uint8Array): [Uint8Array, Uint8Array] {
    const cpaSeed = ikm.subarray(0, 32);
    const z = ikm.subarray(32, 64);

    // IND-CPA keypair
    const cpaKeys = this._deriveCpaKeyPair(cpaSeed);

    const pk = cpaKeys[0];
    const pkh = sha3_256.create().update(pk).digest();
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
    const seed = sha3_512.create().update(cpaSeed).digest();
    const publicSeed = seed.subarray(0, 32);
    const noiseSeed = seed.subarray(32, 64);

    // generate public matrix A (already in NTT form)
    const a = generateMatrixA(publicSeed, false);

    // sample secret s
    const s = new Array<Array<number>>(paramsK);
    let nonce = 0;
    for (let i = 0; i < paramsK; i++) {
      s[i] = sample(noiseSeed, nonce);
      nonce++;
    }

    // sample noise e
    const e = new Array<Array<number>>(paramsK);
    for (let i = 0; i < paramsK; i++) {
      e[i] = sample(noiseSeed, nonce);
      nonce++;
    }

    // perform number theoretic transform on secret s
    for (let i = 0; i < paramsK; i++) {
      s[i] = ntt(s[i]);
    }

    // perform number theoretic transform on error/noise e
    for (let i = 0; i < paramsK; i++) {
      e[i] = ntt(e[i]);
    }

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
      s[i] = reduce(s[i]);
    }

    // KEY COMPUTATION
    // A.s + e = pk

    // calculate A.s
    const pk = new Array<Array<number>>(paramsK);
    for (let i = 0; i < paramsK; i++) {
      // montgomery reduction
      pk[i] = polyToMont(multiply(a[i], s));
    }

    // calculate addition of e
    for (let i = 0; i < paramsK; i++) {
      pk[i] = add(pk[i], e[i]);
    }

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
      pk[i] = reduce(pk[i]);
    }

    // PUBLIC KEY
    // turn polynomials into byte arrays
    const pubKey = new Uint8Array(1184);
    for (let i = 0; i < paramsK; i++) {
      pubKey.set(polyToBytes(pk[i]), i * 384);
    }
    // append public seed
    pubKey.set(publicSeed, 1152);

    // PRIVATE KEY
    // turn polynomials into byte arrays
    const privKey = new Uint8Array(1152);
    for (let i = 0; i < paramsK; i++) {
      privKey.set(polyToBytes(s[i]), i * 384);
    }
    return [pubKey, privKey];
  }

  // _encap is the encapsulation function of the CPA-secure
  // public-key encryption scheme underlying Kyber.
  private _encap(
    pk1: Uint8Array,
    msg: Uint8Array,
    coins: Uint8Array,
  ): Uint8Array {
    const pk = new Array<Array<number>>(paramsK);
    for (let i = 0; i < paramsK; i++) {
      pk[i] = polyFromBytes(pk1.subarray(i * 384, (i + 1) * 384));
    }
    const seed = pk1.subarray(1152, 1184);

    // generate transpose of public matrix A
    const at = generateMatrixA(seed, true);

    // sample random vector r
    const r = new Array<Array<number>>(paramsK);
    let nonce = 0;
    for (let i = 0; i < paramsK; i++) {
      r[i] = sample(coins, nonce);
      nonce++;
    }

    // sample error vector e1
    const e1 = new Array<Array<number>>(paramsK);
    for (let i = 0; i < paramsK; i++) {
      e1[i] = sample(coins, nonce);
      nonce++;
    }

    // sample e2
    const e2 = sample(coins, nonce);

    // perform number theoretic transform on random vector r
    for (let i = 0; i < paramsK; i++) {
      r[i] = ntt(r[i]);
    }

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
      r[i] = reduce(r[i]);
    }

    // ENCRYPT COMPUTATION
    // A.r + e1 = u
    // pk.r + e2 + m = v

    // calculate A.r
    const u = new Array<Array<number>>(paramsK);
    for (let i = 0; i < paramsK; i++) {
      u[i] = multiply(at[i], r);
    }

    // perform inverse number theoretic transform on A.r
    for (let i = 0; i < paramsK; i++) {
      u[i] = nttInverse(u[i]);
    }

    // calculate addition of e1
    for (let i = 0; i < paramsK; i++) {
      u[i] = add(u[i], e1[i]);
    }

    // decode message m
    const m = polyFromMsg(msg);

    // calculate pk.r
    let v = multiply(pk, r);

    // perform inverse number theoretic transform on pk.r
    v = nttInverse(v);

    // calculate addition of e2
    v = add(v, e2);

    // calculate addition of m
    v = add(v, m);

    // barrett reduction
    for (let i = 0; i < paramsK; i++) {
      u[i] = reduce(u[i]);
    }

    // barrett reduction
    v = reduce(v);

    // compress
    const c1 = compress1(u);
    const c2 = compress2(v);

    // return c1 || c2
    return concat(c1, c2);
  }

  // indcpaDecrypt is the decryption function of the CPA-secure
  // public-key encryption scheme underlying Kyber.
  private _decap(c: Uint8Array, privateKey: Uint8Array): Uint8Array {
    // extract ciphertext
    const u = decompress1(c.subarray(0, 960));
    const v = decompress2(c.subarray(960, 1088));

    const privateKeyPolyvec = polyvecFromBytes(privateKey);

    for (let i = 0; i < paramsK; i++) {
      u[i] = ntt(u[i]);
    }

    // ???
    let mp = multiply(privateKeyPolyvec, u);
    mp = nttInverse(mp);
    mp = subtract(v, mp);
    mp = reduce(mp);
    return polyToMsg(mp);
  }

  protected async _setup() {
    if (this._api !== undefined) {
      return;
    }
    this._api = await loadCrypto();
  }
}

async function loadCrypto(): Promise<Crypto> {
  if (isBrowser() || isCloudflareWorkers()) {
    if (globalThis.crypto !== undefined) {
      return globalThis.crypto;
    }
    // jsdom
  }

  try {
    // @ts-ignore: to ignore "crypto"
    const { webcrypto } = await import("crypto"); // node:crypto
    return (webcrypto as unknown as Crypto);
  } catch (_e: unknown) {
    throw new Error("Web Cryptograph API not supported");
  }
}

// polyvecFromBytes deserializes a vector of polynomials.
function polyvecFromBytes(a: Uint8Array): Array<Array<number>> {
  const r = new Array<Array<number>>(paramsK);
  for (let i = 0; i < paramsK; i++) {
    r[i] = new Array<number>(384);
  }
  for (let i = 0; i < paramsK; i++) {
    r[i] = polyFromBytes(a.subarray(i * 384, (i + 1) * 384));
  }
  return r;
}

// polyToBytes serializes a polynomial into an array of bytes.
function polyToBytes(a: Array<number>): Uint8Array {
  let t0 = 0;
  let t1 = 0;
  const r = new Uint8Array(384);
  const a2 = subtract_q(a); // Returns: a - q if a >= q, else a (each coefficient of the polynomial)
  // for 0-127
  for (let i = 0; i < paramsN / 2; i++) {
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
  for (let i = 0; i < paramsN / 2; i++) {
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
  const a2 = subtract_q(a);
  for (let i = 0; i < paramsN / 8; i++) {
    msg[i] = 0;
    for (let j = 0; j < 8; j++) {
      t = (((uint16(a2[8 * i + j]) << 1) + uint16(paramsQ / 2)) /
        uint16(paramsQ)) & 1;
      msg[i] |= byte(t << j);
    }
  }
  return msg;
}

// polyFromMsg converts a 32-byte message to a polynomial.
function polyFromMsg(msg: Uint8Array): Array<number> {
  const r = new Array<number>(384).fill(0); // each element is int16 (0-65535)
  let mask; // int16
  for (let i = 0; i < paramsN / 8; i++) {
    for (let j = 0; j < 8; j++) {
      mask = -1 * int16((msg[i] >> j) & 1);
      r[8 * i + j] = mask & int16((paramsQ + 1) / 2);
    }
  }
  return r;
}

// generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
function generateMatrixA(
  seed: Uint8Array,
  transposed: boolean,
): Array<Array<Array<number>>> {
  const a = new Array<Array<Array<number>>>(3);
  let ctr = 0;
  const transpose = new Uint8Array(2);
  const outputlen = 3 * 168; // 504

  for (let i = 0; i < paramsK; i++) {
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
      const xof = shake128.create({ dkLen: 672 });
      // const output = xof.update(seed).update(Uint8Array.from(transpose)).digest();
      const output = xof.update(seed).update(transpose).digest();

      // run rejection sampling on the output from above
      const result = indcpaRejUniform(
        output.subarray(0, 504),
        outputlen,
        paramsN,
      );
      a[i][j] = result[0]; // the result here is an NTT-representation
      ctr = result[1]; // keeps track of index of output array from sampling function

      while (ctr < paramsN) { // if the polynomial hasnt been filled yet with mod q entries
        const outputn = output.subarray(504, 672); // take last 168 bytes of byte array from xof
        const result1 = indcpaRejUniform(outputn, 168, paramsN - ctr); // run sampling function again
        const missing = result1[0]; // here is additional mod q polynomial coefficients
        const ctrn = result1[1]; // how many coefficients were accepted and are in the output
        // starting at last position of output array from first sampling function until 256 is reached
        for (let k = ctr; k < paramsN; k++) {
          a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
        }
        ctr = ctr + ctrn; // update index
      }
    }
  }
  return a;
}

// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
function indcpaRejUniform(
  buf: Uint8Array,
  bufl: number,
  len: number,
): [Array<number>, number] {
  const r = new Array<number>(384).fill(0);
  let val0, val1; // d1, d2 in kyber documentation
  let pos = 0; // i
  let ctr = 0; // j

  while (ctr < len && pos + 3 <= bufl) {
    // compute d1 and d2
    val0 = (uint16((buf[pos]) >> 0) | (uint16(buf[pos + 1]) << 8)) & 0xFFF;
    val1 = (uint16((buf[pos + 1]) >> 4) | (uint16(buf[pos + 2]) << 4)) & 0xFFF;

    // increment input buffer index by 3
    pos = pos + 3;

    // if d1 is less than 3329
    if (val0 < paramsQ) {
      // assign to d1
      r[ctr] = val0;
      // increment position of output array
      ctr = ctr + 1;
    }
    if (ctr < len && val1 < paramsQ) {
      r[ctr] = val1;
      ctr = ctr + 1;
    }
  }
  return [r, ctr];
}

// sample samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution with parameter paramsETA = 2.
function sample(seed: Uint8Array, nonce: number): Array<number> {
  const l = paramsETA * paramsN / 4;
  const p = prf(l, seed, nonce);
  return byteopsCbd(p);
}

// prf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
function prf(l: number, key: Uint8Array, nonce: number): Uint8Array {
  const nonce_arr = new Uint8Array(1);
  nonce_arr[0] = nonce;
  // const hash = new SHAKE(256);
  // hash.reset();
  // const buffer1 = Buffer.from(key);
  // const buffer2 = Buffer.from(nonce_arr);
  // hash.update(buffer1).update(buffer2);
  // let buf = hash.digest({ buffer: Buffer.alloc(l)}); // 128 long byte array
  // return buf;
  return shake256.create({ dkLen: l }).update(key).update(nonce_arr).digest();
}

// byteopsCbd computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter paramsETA,
// given an array of uniformly random bytes.
function byteopsCbd(buf: Uint8Array): Array<number> {
  let t, d;
  let a, b;
  const r = new Array<number>(384).fill(0);
  for (let i = 0; i < paramsN / 8; i++) {
    t = byteopsLoad32(buf.subarray(4 * i, buf.length)) >>> 0;
    d = (t & 0x55555555) >>> 0;
    d = d + ((((t >> 1) >>> 0) & 0x55555555) >>> 0) >>> 0;
    for (let j = 0; j < 8; j++) {
      a = int16((((d >> (4 * j + 0)) >>> 0) & 0x3) >>> 0);
      b = int16((((d >> (4 * j + paramsETA)) >>> 0) & 0x3) >>> 0);
      r[8 * i + j] = a - b;
    }
  }
  return r;
}

// byteopsLoad32 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad32(x: Uint8Array): number {
  let r;
  r = uint32(x[0]);
  r = ((r | (uint32(x[1]) << 8)) >>> 0) >>> 0;
  r = ((r | (uint32(x[2]) << 16)) >>> 0) >>> 0;
  r = ((r | (uint32(x[3]) << 24)) >>> 0) >>> 0;
  return uint32(r);
}

// ntt performs an inplace number-theoretic transform (NTT) in `Rq`.
// The input is in standard order, the output is in bit-reversed order.
function ntt(r: Array<number>): Array<number> {
  let j = 0;
  let k = 1;
  let zeta;
  let t;
  // 128, 64, 32, 16, 8, 4, 2
  for (let l = 128; l >= 2; l >>= 1) {
    // 0,
    for (let start = 0; start < 256; start = j + l) {
      zeta = nttZetas[k];
      k = k + 1;
      // for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
      for (j = start; j < start + l; j++) {
        // compute the modular multiplication of the zeta and each element in the subsection
        t = nttFqMul(zeta, r[j + l]); // t is mod q
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
  for (let i = 0; i < paramsN; i++) {
    r[i] = barrett(r[i]);
  }
  return r;
}

// barrett computes a Barrett reduction; given
// a integer `a`, returns a integer congruent to
// `a mod Q` in {0,...,Q}.
function barrett(a: number): number {
  const v = ((1 << 24) + paramsQ / 2) / paramsQ;
  let t = v * a >> 24;
  t = t * paramsQ;
  return a - t;
}

// byteopsMontgomeryReduce computes a Montgomery reduction; given
// a 32-bit integer `a`, returns `a * R^-1 mod Q` where `R=2^16`.
function byteopsMontgomeryReduce(a: number): number {
  const u = int16(int32(a) * paramsQinv);
  let t = u * paramsQ;
  t = a - t;
  t >>= 16;
  return int16(t);
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
function polyToMont(r: Array<number>): Array<number> {
  // let f = int16(((uint64(1) << 32) >>> 0) % uint64(paramsQ));
  const f = 1353; // if paramsQ changes then this needs to be updated
  for (let i = 0; i < paramsN; i++) {
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
  for (let i = 1; i < paramsK; i++) {
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
  for (let i = 0; i < paramsN / 4; i++) {
    rx = nttBaseMul(
      a[4 * i + 0],
      a[4 * i + 1],
      b[4 * i + 0],
      b[4 * i + 1],
      nttZetas[64 + i],
    );
    ry = nttBaseMul(
      a[4 * i + 2],
      a[4 * i + 3],
      b[4 * i + 2],
      b[4 * i + 3],
      -nttZetas[64 + i],
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
  for (let i = 0; i < paramsN; i++) {
    c[i] = a[i] + b[i];
  }
  return c;
}

// subtracts two polynomials.
function subtract(a: Array<number>, b: Array<number>): Array<number> {
  for (let i = 0; i < paramsN; i++) {
    a[i] = a[i] - b[i];
  }
  return a;
}

// nttInverse performs an inplace inverse number-theoretic transform (NTT)
// in `Rq` and multiplication by Montgomery factor 2^16.
// The input is in bit-reversed order, the output is in standard order.
function nttInverse(r: Array<number>): Array<number> {
  let j = 0;
  let k = 0;
  let zeta;
  let t;
  for (let l = 2; l <= 128; l <<= 1) {
    for (let start = 0; start < 256; start = j + l) {
      zeta = nttZetasInv[k];
      k = k + 1;
      for (j = start; j < start + l; j++) {
        t = r[j];
        r[j] = barrett(t + r[j + l]);
        r[j + l] = t - r[j + l];
        r[j + l] = nttFqMul(zeta, r[j + l]);
      }
    }
  }
  for (j = 0; j < 256; j++) {
    r[j] = nttFqMul(r[j], nttZetasInv[127]);
  }
  return r;
}

// compress1 lossily compresses and serializes a vector of polynomials.
function compress1(u: Array<Array<number>>): Uint8Array {
  let rr = 0;
  const r = new Uint8Array(960);
  const t = new Array<number>(4);
  for (let i = 0; i < paramsK; i++) {
    for (let j = 0; j < paramsN / 4; j++) {
      for (let k = 0; k < 4; k++) {
        // parse {0,...,3328} to {0,...,1023}
        t[k] = (((u[i][4 * j + k] << 10) + paramsQ / 2) / paramsQ) &
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
function compress2(v: Array<number>): Uint8Array {
  let rr = 0;
  const r = new Uint8Array(128);
  const t = new Uint8Array(8);
  for (let i = 0; i < paramsN / 8; i++) {
    for (let j = 0; j < 8; j++) {
      t[j] = byte(((v[8 * i + j] << 4) + paramsQ / 2) / paramsQ) & 0b1111;
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
function decompress1(a: Uint8Array): Array<Array<number>> {
  const r = new Array<Array<number>>(paramsK);
  for (let i = 0; i < paramsK; i++) {
    r[i] = new Array<number>(384);
  }
  let aa = 0;
  const t = new Array<number>(4);
  for (let i = 0; i < paramsK; i++) {
    for (let j = 0; j < paramsN / 4; j++) {
      t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
      t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
      t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
      t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
      aa = aa + 5;
      for (let k = 0; k < 4; k++) {
        r[i][4 * j + k] = int16(
          (((uint32(t[k] & 0x3FF) >>> 0) * (uint32(paramsQ) >>> 0) >>> 0) +
                512) >> 10 >>> 0,
        );
      }
    }
  }
  return r;
}

// subtract_q applies the conditional subtraction of q to each coefficient of a polynomial.
// if a is 3329 then convert to 0
// Returns:     a - q if a >= q, else a
function subtract_q(r: Array<number>): Array<number> {
  for (let i = 0; i < paramsN; i++) {
    r[i] = r[i] - paramsQ; // should result in a negative integer
    // push left most signed bit to right most position
    // javascript does bitwise operations in signed 32 bit
    // add q back again if left most bit was 0 (positive number)
    r[i] = r[i] + ((r[i] >> 31) & paramsQ);
  }
  return r;
}

// decompress2 de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of compress2.
// Note that compression is lossy, and thus decompression will not match the
// original input.
function decompress2(a: Uint8Array): Array<number> {
  const r = new Array<number>(384);
  let aa = 0;
  for (let i = 0; i < paramsN / 2; i++) {
    r[2 * i + 0] = int16(((uint16(a[aa] & 15) * uint16(paramsQ)) + 8) >> 4);
    r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(paramsQ)) + 8) >> 4);
    aa = aa + 1;
  }
  return r;
}

function byte(n: number): number {
  return n % 256;
}

function int16(n: number): number {
  const end = -32768;
  const start = 32767;

  if (n >= end && n <= start) {
    return n;
  }
  if (n < end) {
    n = n + 32769;
    n = n % 65536;
    return start + n;
  }
  // if (n > start) {
  n = n - 32768;
  n = n % 65536;
  return end + n;
}

function uint16(n: number): number {
  return n % 65536;
}

function int32(n: number): number {
  const end = -2147483648;
  const start = 2147483647;

  if (n >= end && n <= start) {
    return n;
  }
  if (n < end) {
    n = n + 2147483649;
    n = n % 4294967296;
    return start + n;
  }
  // if (n > start) {
  n = n - 2147483648;
  n = n % 4294967296;
  return end + n;
}

// any bit operations to be done in uint32 must have >>> 0
// javascript calculates bitwise in SIGNED 32 bit so you need to convert
function uint32(n: number): number {
  return n % 4294967296;
}

// compares two arrays and returns 1 if they are the same or 0 if not
function compareArray(a: Uint8Array, b: Uint8Array): boolean {
  // check array lengths
  if (a.length != b.length) {
    return false;
  }
  // check contents
  for (let i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}
