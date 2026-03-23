import type { DhkemPrimitives, KdfInterface } from "@hpke/common";

import {
  DeriveKeyPairError,
  DeserializeError,
  EMPTY,
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
  loadCrypto,
  NotSupportedError,
  SerializeError,
  toArrayBuffer,
  XCryptoKey,
} from "@hpke/common";

const ALG_NAME = "ECDH";

// secp256k1 curve parameters
const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// secp256k1: y² = x³ + 7 (a = 0, b = 7)

type Point = { x: bigint; y: bigint } | null;

// =========================================================================
// Modular arithmetic
// =========================================================================

function mod(a: bigint, b: bigint): bigint {
  const r = a % b;
  return r >= 0n ? r : b + r;
}

function modPow(base: bigint, exponent: bigint, p: bigint): bigint {
  let result = 1n;
  let b = mod(base, p);
  let e = exponent;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = result * b % p;
    }
    b = b * b % p;
    e >>= 1n;
  }
  return result;
}

function modInverse(a: bigint): bigint {
  return modPow(a, P - 2n, P);
}

function modSqrt(a: bigint): bigint {
  const y = modPow(a, (P + 1n) >> 2n, P);
  if (y * y % P !== mod(a, P)) {
    throw new Error("No square root exists");
  }
  return y;
}

// =========================================================================
// Jacobian coordinates: (X : Y : Z) represents affine (X/Z², Y/Z³)
// Point at infinity: Z = 0
// =========================================================================

// Jacobian doubling (a = 0 for secp256k1)
function jDouble(
  px: bigint,
  py: bigint,
  pz: bigint,
): [bigint, bigint, bigint] {
  if (pz === 0n) return [0n, 1n, 0n];
  const yy = py * py % P;
  const s = 4n * (px * yy % P) % P;
  const m = 3n * (px * px % P) % P;
  const t = mod(m * m % P - 2n * s, P);
  return [
    t,
    mod(m * mod(s - t, P) % P - 8n * (yy * yy % P) % P, P),
    2n * (py * pz % P) % P,
  ];
}

// Jacobian addition (general)
function jAdd(
  p1x: bigint,
  p1y: bigint,
  p1z: bigint,
  p2x: bigint,
  p2y: bigint,
  p2z: bigint,
): [bigint, bigint, bigint] {
  if (p1z === 0n) return [p2x, p2y, p2z];
  if (p2z === 0n) return [p1x, p1y, p1z];
  const z1z1 = p1z * p1z % P;
  const z2z2 = p2z * p2z % P;
  const u1 = p1x * z2z2 % P;
  const u2 = p2x * z1z1 % P;
  const s1 = p1y * p2z % P * z2z2 % P;
  const s2 = p2y * p1z % P * z1z1 % P;
  const h = mod(u2 - u1, P);
  const r = mod(s2 - s1, P);
  if (h === 0n) {
    if (r === 0n) return jDouble(p1x, p1y, p1z);
    return [0n, 1n, 0n];
  }
  const hh = h * h % P;
  const hhh = h * hh % P;
  const v = u1 * hh % P;
  const x3 = mod(r * r % P - hhh - 2n * v, P);
  return [
    x3,
    mod(r * mod(v - x3, P) % P - s1 * hhh % P, P),
    h * p1z % P * p2z % P,
  ];
}

// Mixed addition: Jacobian + affine (Z2 = 1), saves multiplications
function jAddMixed(
  p1x: bigint,
  p1y: bigint,
  p1z: bigint,
  ax: bigint,
  ay: bigint,
): [bigint, bigint, bigint] {
  if (p1z === 0n) return [ax, ay, 1n];
  const zz = p1z * p1z % P;
  const u2 = ax * zz % P;
  const s2 = ay * p1z % P * zz % P;
  const h = mod(u2 - p1x, P);
  const r = mod(s2 - p1y, P);
  if (h === 0n) {
    if (r === 0n) return jDouble(p1x, p1y, p1z);
    return [0n, 1n, 0n];
  }
  const hh = h * h % P;
  const hhh = h * hh % P;
  const v = p1x * hh % P;
  const x3 = mod(r * r % P - hhh - 2n * v, P);
  return [
    x3,
    mod(r * mod(v - x3, P) % P - p1y * hhh % P, P),
    h * p1z % P,
  ];
}

function jToAffine(
  px: bigint,
  py: bigint,
  pz: bigint,
): Point {
  if (pz === 0n) return null;
  if (pz === 1n) return { x: px, y: py };
  const zi = modInverse(pz);
  const zi2 = zi * zi % P;
  return {
    x: px * zi2 % P,
    y: py * zi % P * zi2 % P,
  };
}

// =========================================================================
// wNAF scalar multiplication
// =========================================================================

const WNAF_W = 5;
const WNAF_PRECOMP_COUNT = 1 << (WNAF_W - 1); // 16

function toWNAF(k: bigint): Int8Array {
  const wnaf = new Int8Array(257);
  const mask = BigInt((1 << WNAF_W) - 1);
  const half = 1 << (WNAF_W - 1);
  let n = k;
  let i = 0;
  while (n > 0n) {
    if (n & 1n) {
      let val = Number(n & mask);
      if (val >= half) {
        val -= 1 << WNAF_W;
      }
      n -= BigInt(val);
      wnaf[i] = val;
    }
    n >>= 1n;
    i++;
  }
  return wnaf.subarray(0, i);
}

// Build wNAF precomputed table: [1]P, [3]P, [5]P, ..., [2^(w-1)-1]P
// Returns Jacobian points (avoids expensive per-point inversion)
function buildPrecomp(
  ax: bigint,
  ay: bigint,
): [bigint, bigint, bigint][] {
  const table: [bigint, bigint, bigint][] = new Array(WNAF_PRECOMP_COUNT);
  table[0] = [ax, ay, 1n];
  const d = jDouble(ax, ay, 1n);
  for (let i = 1; i < WNAF_PRECOMP_COUNT; i++) {
    table[i] = jAdd(
      table[i - 1][0],
      table[i - 1][1],
      table[i - 1][2],
      d[0],
      d[1],
      d[2],
    );
  }
  return table;
}

function scalarMultWnaf(
  k: bigint,
  precomp: [bigint, bigint, bigint][],
): Point {
  const wnaf = toWNAF(k);
  let rx = 0n, ry = 1n, rz = 0n;
  for (let i = wnaf.length - 1; i >= 0; i--) {
    [rx, ry, rz] = jDouble(rx, ry, rz);
    const d = wnaf[i];
    if (d > 0) {
      const p = precomp[(d - 1) >> 1];
      [rx, ry, rz] = jAdd(rx, ry, rz, p[0], p[1], p[2]);
    } else if (d < 0) {
      const p = precomp[(-d - 1) >> 1];
      [rx, ry, rz] = jAdd(rx, ry, rz, p[0], mod(P - p[1], P), p[2]);
    }
  }
  return jToAffine(rx, ry, rz);
}

// =========================================================================
// Fixed-base windowed multiplication for generator G.
//
// Uses w=8 signed-digit decomposition: 256-bit scalar is split into 33
// windows of 8 bits each (signed, range [-128, 128]).
// For each window position i, we precompute [1]*B, [2]*B, ..., [128]*B
// where B = 2^(8*i) * G, stored as affine points.
//
// Multiplication is just ~33 mixed additions — no doublings at all.
// The table (33 * 128 = 4224 affine points) is computed lazily once.
// =========================================================================

const G_WIN = 8;
const G_WIN_SIZE = 1 << (G_WIN - 1); // 128
const G_WIN_GROUPS = 33; // ceil(256/8) + 1 for carry

let _gTable: { x: bigint; y: bigint }[][] | undefined;

function batchJToAffine(
  pts: [bigint, bigint, bigint][],
): { x: bigint; y: bigint }[] {
  const n = pts.length;
  // Montgomery's trick: one modInverse for all points
  const zs = new Array<bigint>(n);
  for (let i = 0; i < n; i++) zs[i] = pts[i][2];
  const prods = new Array<bigint>(n);
  prods[0] = zs[0];
  for (let i = 1; i < n; i++) prods[i] = prods[i - 1] * zs[i] % P;
  let inv = modInverse(prods[n - 1]);
  const zInvs = new Array<bigint>(n);
  for (let i = n - 1; i > 0; i--) {
    zInvs[i] = inv * prods[i - 1] % P;
    inv = inv * zs[i] % P;
  }
  zInvs[0] = inv;
  const out = new Array<{ x: bigint; y: bigint }>(n);
  for (let i = 0; i < n; i++) {
    const zi2 = zInvs[i] * zInvs[i] % P;
    out[i] = {
      x: pts[i][0] * zi2 % P,
      y: pts[i][1] * zInvs[i] % P * zi2 % P,
    };
  }
  return out;
}

function getGTable(): { x: bigint; y: bigint }[][] {
  if (_gTable) return _gTable;
  // Build all Jacobian points, then batch-convert to affine
  const allJ: [bigint, bigint, bigint][] = [];
  let bx = Gx, by = Gy, bz = 1n; // base = 2^(g*8) * G
  for (let g = 0; g < G_WIN_GROUPS; g++) {
    // Multiples [1]*base, [2]*base, ..., [128]*base
    let cx = bx, cy = by, cz = bz;
    allJ.push([cx, cy, cz]);
    for (let j = 1; j < G_WIN_SIZE; j++) {
      // mixed add when base z=1 (only first group), else full Jacobian add
      if (bz === 1n) {
        [cx, cy, cz] = jAddMixed(cx, cy, cz, bx, by);
      } else {
        [cx, cy, cz] = jAdd(cx, cy, cz, bx, by, bz);
      }
      allJ.push([cx, cy, cz]);
    }
    // Advance: base = 2^8 * base
    for (let j = 0; j < G_WIN; j++) [bx, by, bz] = jDouble(bx, by, bz);
  }
  // Batch convert to affine
  const affine = batchJToAffine(allJ);
  // Organize into groups
  _gTable = new Array(G_WIN_GROUPS);
  let idx = 0;
  for (let g = 0; g < G_WIN_GROUPS; g++) {
    _gTable[g] = affine.slice(idx, idx + G_WIN_SIZE);
    idx += G_WIN_SIZE;
  }
  return _gTable;
}

function scalarMultG(k: bigint): Point {
  const table = getGTable();
  // Signed-digit decomposition: split k into 8-bit signed windows
  const mask = 0xFFn;
  let n = k;
  let rx = 0n, ry = 1n, rz = 0n;
  for (let g = 0; g < G_WIN_GROUPS; g++) {
    let d = Number(n & mask);
    n >>= 8n;
    if (d >= G_WIN_SIZE) {
      d -= 1 << G_WIN;
      n += 1n; // carry
    }
    if (d > 0) {
      const p = table[g][d - 1];
      [rx, ry, rz] = jAddMixed(rx, ry, rz, p.x, p.y);
    } else if (d < 0) {
      const p = table[g][-d - 1];
      [rx, ry, rz] = jAddMixed(rx, ry, rz, p.x, P - p.y);
    }
  }
  return jToAffine(rx, ry, rz);
}

// =========================================================================
// Public key / ECDH functions
// =========================================================================

function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) {
    v = (v << 8n) | BigInt(b);
  }
  return v;
}

function bigIntToBytes(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let n = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function compressPoint(point: { x: bigint; y: bigint }): Uint8Array {
  const prefix = (point.y & 1n) === 0n ? 0x02 : 0x03;
  const out = new Uint8Array(33);
  out[0] = prefix;
  out.set(bigIntToBytes(point.x, 32), 1);
  return out;
}

function decompressPoint(
  compressed: Uint8Array,
): { x: bigint; y: bigint } {
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error("Invalid compressed point prefix");
  }
  const x = bytesToBigInt(compressed.subarray(1, 33));
  const rhs = mod(x * x % P * x % P + 7n, P);
  let y = modSqrt(rhs);
  if (
    (prefix === 0x02 && (y & 1n) === 1n) ||
    (prefix === 0x03 && (y & 1n) === 0n)
  ) {
    y = P - y;
  }
  return { x, y };
}

function getPublicKey(privateKey: Uint8Array): Uint8Array {
  const k = bytesToBigInt(privateKey);
  if (k === 0n || k >= N) {
    throw new Error("Invalid private key");
  }
  const pub = scalarMultG(k);
  if (pub === null) {
    throw new Error("Invalid result");
  }
  return compressPoint(pub);
}

function getSharedSecret(
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Uint8Array {
  const k = bytesToBigInt(privateKey);
  if (k === 0n || k >= N) {
    throw new Error("Invalid private key");
  }

  let point: { x: bigint; y: bigint };
  if (publicKey.length === 33) {
    point = decompressPoint(publicKey);
  } else if (publicKey.length === 65 && publicKey[0] === 0x04) {
    point = {
      x: bytesToBigInt(publicKey.subarray(1, 33)),
      y: bytesToBigInt(publicKey.subarray(33, 65)),
    };
  } else {
    throw new Error("Invalid public key");
  }

  const precomp = buildPrecomp(point.x, point.y);
  const shared = scalarMultWnaf(k, precomp);
  if (shared === null) {
    throw new Error("Invalid shared secret");
  }
  return compressPoint(shared);
}

// =========================================================================
// Secp256k1 class (DhkemPrimitives implementation)
// =========================================================================

export class Secp256k1 implements DhkemPrimitives {
  private _hkdf: KdfInterface;
  private _nPk: number;
  private _nSk: number;

  constructor(hkdf: KdfInterface) {
    this._hkdf = hkdf;
    this._nPk = 33;
    this._nSk = 32;
  }

  public async serializePublicKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePublicKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    try {
      return await this._importRawKey(toArrayBuffer(key), true);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async serializePrivateKey(key: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._serializePrivateKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  public async deserializePrivateKey(
    key: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKey> {
    try {
      return await this._importRawKey(toArrayBuffer(key), false);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async importKey(
    format: "raw",
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    try {
      if (format !== "raw") {
        throw new Error("Unsupported format");
      }
      return await this._importRawKey(key, isPublic);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      const cryptoApi = await loadCrypto();
      let rawSk: Uint8Array;
      while (true) {
        const candidate = new Uint8Array(32);
        cryptoApi.getRandomValues(candidate);
        const k = bytesToBigInt(candidate);
        if (k > 0n && k < N) {
          rawSk = candidate;
          break;
        }
      }
      const sk = new XCryptoKey(ALG_NAME, rawSk, "private", KEM_USAGES);
      const pk = await this.derivePublicKey(sk);
      return { publicKey: pk, privateKey: sk };
    } catch (e: unknown) {
      throw new NotSupportedError(e);
    }
  }

  public async deriveKeyPair(
    ikm: ArrayBufferLike | ArrayBufferView,
  ): Promise<CryptoKeyPair> {
    try {
      const rawIkm = toArrayBuffer(ikm);
      const dkpPrk = await this._hkdf.labeledExtract(
        EMPTY,
        LABEL_DKP_PRK,
        new Uint8Array(rawIkm),
      );
      const rawSk = await this._hkdf.labeledExpand(
        dkpPrk,
        LABEL_SK,
        EMPTY,
        this._nSk,
      );
      const sk = new XCryptoKey(
        ALG_NAME,
        new Uint8Array(rawSk),
        "private",
        KEM_USAGES,
      );
      return {
        privateKey: sk,
        publicKey: await this.derivePublicKey(sk),
      };
    } catch (e: unknown) {
      throw new DeriveKeyPairError(e);
    }
  }

  public async derivePublicKey(key: CryptoKey): Promise<CryptoKey> {
    try {
      return await this._derivePublicKey(key as XCryptoKey);
    } catch (e: unknown) {
      throw new DeserializeError(e);
    }
  }

  public async dh(sk: CryptoKey, pk: CryptoKey): Promise<ArrayBuffer> {
    try {
      return await this._dh(sk as XCryptoKey, pk as XCryptoKey);
    } catch (e: unknown) {
      throw new SerializeError(e);
    }
  }

  private _serializePublicKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      resolve(k.key.buffer as ArrayBuffer);
    });
  }

  private _serializePrivateKey(k: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve) => {
      resolve(k.key.buffer as ArrayBuffer);
    });
  }

  private _importRawKey(
    key: ArrayBuffer,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      if (isPublic && key.byteLength !== this._nPk) {
        reject(new Error("Invalid length of the key"));
      }
      if (!isPublic && key.byteLength !== this._nSk) {
        reject(new Error("Invalid length of the key"));
      }
      resolve(
        new XCryptoKey(
          ALG_NAME,
          new Uint8Array(key),
          isPublic ? "public" : "private",
          isPublic ? [] : KEM_USAGES,
        ),
      );
    });
  }

  private _derivePublicKey(k: XCryptoKey): Promise<CryptoKey> {
    return new Promise((resolve, reject) => {
      try {
        const pk = getPublicKey(k.key);
        resolve(new XCryptoKey(ALG_NAME, pk, "public"));
      } catch (e: unknown) {
        reject(e);
      }
    });
  }

  private _dh(sk: XCryptoKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      try {
        resolve(
          getSharedSecret(sk.key, pk.key).buffer as ArrayBuffer,
        );
      } catch (e: unknown) {
        reject(e);
      }
    });
  }
}
