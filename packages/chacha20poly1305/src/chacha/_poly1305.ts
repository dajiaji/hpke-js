/**
 * This file is based on noble-ciphers (https://github.com/paulmillr/noble-ciphers).
 *
 * noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-ciphers/blob/749cdf9cd07ebdd19e9b957d0f172f1045179695/src/_poly1305.ts
 */

/**
 * Poly1305 ([PDF](https://cr.yp.to/mac/poly1305-20050329.pdf),
 * [wiki](https://en.wikipedia.org/wiki/Poly1305)) specialized for the
 * AEAD_CHACHA20_POLY1305 construction of
 * [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
 *
 * The AEAD only ever authenticates 16-byte blocks (the AAD and the ciphertext
 * are zero-padded and followed by a block of lengths), so the generic
 * incremental interface, its partial-block buffering and the short final block
 * handling of the original implementation are not needed here.
 *
 * Based on Public Domain [poly1305-donna](https://github.com/floodyberry/poly1305-donna).
 * @module
 */

const u16 = (a: Uint8Array, i: number): number => a[i] | (a[i + 1] << 8);

/**
 * Absorbs the 16-byte blocks m[pos..end) into the Poly1305 state.
 * st = h[0..10) || r[10..20), 13-bit limbs.
 */
function polyBlocks(
  st: Uint16Array,
  m: Uint8Array,
  pos: number,
  end: number,
): void {
  const r0 = st[10],
    r1 = st[11],
    r2 = st[12],
    r3 = st[13],
    r4 = st[14],
    r5 = st[15],
    r6 = st[16],
    r7 = st[17],
    r8 = st[18],
    r9 = st[19];
  const s1 = 5 * r1,
    s2 = 5 * r2,
    s3 = 5 * r3,
    s4 = 5 * r4,
    s5 = 5 * r5,
    s6 = 5 * r6,
    s7 = 5 * r7,
    s8 = 5 * r8,
    s9 = 5 * r9;
  let h0 = st[0],
    h1 = st[1],
    h2 = st[2],
    h3 = st[3],
    h4 = st[4],
    h5 = st[5],
    h6 = st[6],
    h7 = st[7],
    h8 = st[8],
    h9 = st[9];
  for (; pos < end; pos += 16) {
    const t0 = u16(m, pos),
      t1 = u16(m, pos + 2),
      t2 = u16(m, pos + 4),
      t3 = u16(m, pos + 6),
      t4 = u16(m, pos + 8),
      t5 = u16(m, pos + 10),
      t6 = u16(m, pos + 12),
      t7 = u16(m, pos + 14);
    h0 += t0 & 0x1fff;
    h1 += ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
    h2 += ((t1 >>> 10) | (t2 << 6)) & 0x1fff;
    h3 += ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
    h4 += ((t3 >>> 4) | (t4 << 12)) & 0x1fff;
    h5 += (t4 >>> 1) & 0x1fff;
    h6 += ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
    h7 += ((t5 >>> 11) | (t6 << 5)) & 0x1fff;
    h8 += ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
    h9 += (t7 >>> 5) | 0x800;

    let d0 = h0 * r0 + h1 * s9 + h2 * s8 + h3 * s7 + h4 * s6;
    let c = d0 >>> 13;
    d0 &= 0x1fff;
    d0 += h5 * s5 + h6 * s4 + h7 * s3 + h8 * s2 + h9 * s1;
    c += d0 >>> 13;
    d0 &= 0x1fff;

    let d1 = c + h0 * r1 + h1 * r0 + h2 * s9 + h3 * s8 + h4 * s7;
    c = d1 >>> 13;
    d1 &= 0x1fff;
    d1 += h5 * s6 + h6 * s5 + h7 * s4 + h8 * s3 + h9 * s2;
    c += d1 >>> 13;
    d1 &= 0x1fff;

    let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * s9 + h4 * s8;
    c = d2 >>> 13;
    d2 &= 0x1fff;
    d2 += h5 * s7 + h6 * s6 + h7 * s5 + h8 * s4 + h9 * s3;
    c += d2 >>> 13;
    d2 &= 0x1fff;

    let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s9;
    c = d3 >>> 13;
    d3 &= 0x1fff;
    d3 += h5 * s8 + h6 * s7 + h7 * s6 + h8 * s5 + h9 * s4;
    c += d3 >>> 13;
    d3 &= 0x1fff;

    let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    c = d4 >>> 13;
    d4 &= 0x1fff;
    d4 += h5 * s9 + h6 * s8 + h7 * s7 + h8 * s6 + h9 * s5;
    c += d4 >>> 13;
    d4 &= 0x1fff;

    let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
    c = d5 >>> 13;
    d5 &= 0x1fff;
    d5 += h5 * r0 + h6 * s9 + h7 * s8 + h8 * s7 + h9 * s6;
    c += d5 >>> 13;
    d5 &= 0x1fff;

    let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
    c = d6 >>> 13;
    d6 &= 0x1fff;
    d6 += h5 * r1 + h6 * r0 + h7 * s9 + h8 * s8 + h9 * s7;
    c += d6 >>> 13;
    d6 &= 0x1fff;

    let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
    c = d7 >>> 13;
    d7 &= 0x1fff;
    d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * s9 + h9 * s8;
    c += d7 >>> 13;
    d7 &= 0x1fff;

    let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
    c = d8 >>> 13;
    d8 &= 0x1fff;
    d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * s9;
    c += d8 >>> 13;
    d8 &= 0x1fff;

    let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
    c = d9 >>> 13;
    d9 &= 0x1fff;
    d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
    c += d9 >>> 13;
    d9 &= 0x1fff;

    c = ((c << 2) + c) | 0;
    c = (c + d0) | 0;
    h0 = c & 0x1fff;
    h1 = d1 + (c >>> 13);
    h2 = d2;
    h3 = d3;
    h4 = d4;
    h5 = d5;
    h6 = d6;
    h7 = d7;
    h8 = d8;
    h9 = d9;
  }
  st[0] = h0;
  st[1] = h1;
  st[2] = h2;
  st[3] = h3;
  st[4] = h4;
  st[5] = h5;
  st[6] = h6;
  st[7] = h7;
  st[8] = h8;
  st[9] = h9;
}

/**
 * Poly1305 tag over pad16(aad) || pad16(ct[0..ctLen)) || len(aad) || len(ct).
 * `pk` holds the 32-byte one-time key in its first 32 bytes.
 */
export function poly1305Tag(
  pk: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
  ctLen: number,
): Uint8Array {
  const t0 = u16(pk, 0),
    t1 = u16(pk, 2),
    t2 = u16(pk, 4),
    t3 = u16(pk, 6),
    t4 = u16(pk, 8),
    t5 = u16(pk, 10),
    t6 = u16(pk, 12),
    t7 = u16(pk, 14);
  const h = new Uint16Array(20);
  h[10] = t0 & 0x1fff;
  h[11] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
  h[12] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
  h[13] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
  h[14] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
  h[15] = (t4 >>> 1) & 0x1ffe;
  h[16] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
  h[17] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
  h[18] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
  h[19] = (t7 >>> 5) & 0x007f;
  // Scratch block: zero-padded tails, the lengths block, and finally the tag.
  const t = new Uint8Array(16);
  const aLen = aad.length;
  for (let i = 0; i < 2; i++) {
    const m = i ? ct : aad;
    const len = i ? ctLen : aLen;
    const full = len - (len % 16);
    polyBlocks(h, m, 0, full);
    if (full < len) {
      t.fill(0);
      t.set(m.subarray(full, len));
      polyBlocks(h, t, 0, 16);
    }
  }
  const v = new DataView(t.buffer);
  v.setUint32(0, aLen, true);
  v.setUint32(4, aLen / 0x100000000, true);
  v.setUint32(8, ctLen, true);
  v.setUint32(12, ctLen / 0x100000000, true);
  polyBlocks(h, t, 0, 16);

  // Final reduction and addition of the pad (s). Identical to the
  // poly1305-donna-16 based code currently in _poly1305.ts.
  const g = new Uint16Array(10);
  let c = h[1] >>> 13;
  h[1] &= 0x1fff;
  for (let i = 2; i < 10; i++) {
    h[i] += c;
    c = h[i] >>> 13;
    h[i] &= 0x1fff;
  }
  h[0] += c * 5;
  c = h[0] >>> 13;
  h[0] &= 0x1fff;
  h[1] += c;
  c = h[1] >>> 13;
  h[1] &= 0x1fff;
  h[2] += c;

  g[0] = h[0] + 5;
  c = g[0] >>> 13;
  g[0] &= 0x1fff;
  for (let i = 1; i < 10; i++) {
    g[i] = h[i] + c;
    c = g[i] >>> 13;
    g[i] &= 0x1fff;
  }
  g[9] -= 1 << 13;

  let mask = (c ^ 1) - 1;
  for (let i = 0; i < 10; i++) g[i] &= mask;
  mask = ~mask;
  for (let i = 0; i < 10; i++) h[i] = (h[i] & mask) | g[i];
  h[0] = (h[0] | (h[1] << 13)) & 0xffff;
  h[1] = ((h[1] >>> 3) | (h[2] << 10)) & 0xffff;
  h[2] = ((h[2] >>> 6) | (h[3] << 7)) & 0xffff;
  h[3] = ((h[3] >>> 9) | (h[4] << 4)) & 0xffff;
  h[4] = ((h[4] >>> 12) | (h[5] << 1) | (h[6] << 14)) & 0xffff;
  h[5] = ((h[6] >>> 2) | (h[7] << 11)) & 0xffff;
  h[6] = ((h[7] >>> 5) | (h[8] << 8)) & 0xffff;
  h[7] = ((h[8] >>> 8) | (h[9] << 5)) & 0xffff;

  let f = 0;
  for (let i = 0; i < 8; i++) {
    f = h[i] + u16(pk, 16 + 2 * i) + (f >>> 16);
    t[2 * i] = f;
    t[2 * i + 1] = f >>> 8;
  }
  h.fill(0);
  g.fill(0);
  return t;
}
