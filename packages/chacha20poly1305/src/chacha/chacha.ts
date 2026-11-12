/**
 * This file is based on noble-ciphers (https://github.com/paulmillr/noble-ciphers).
 *
 * noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-ciphers/blob/749cdf9cd07ebdd19e9b957d0f172f1045179695/src/chacha.ts
 */

/**
 * ChaCha20-Poly1305 AEAD from [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439),
 * specialized for the HPKE AEAD interface: one-shot seal/open with a 32-byte
 * key, a 12-byte nonce and a freshly allocated output.
 *
 * ChaCha stream cipher was released in 2008. Check out
 * [PDF](http://cr.yp.to/chacha/chacha-20080128.pdf) and
 * [wiki](https://en.wikipedia.org/wiki/Salsa20) and
 * [website](https://cr.yp.to/chacha.html).
 *
 * @module
 */
import { isLE } from "@hpke/common";

import { poly1305Tag } from "./_poly1305.ts";

const rotl = (a: number, b: number): number => (a << b) | (a >>> (32 - b));

/** Reads a little-endian u32 at any alignment. */
const le32 = (a: Uint8Array, i: number): number =>
  a[i] | (a[i + 1] << 8) | (a[i + 2] << 16) | (a[i + 3] << 24);

/**
 * XORs the ChaCha20 keystream block for (key, nonce words, counter) into
 * o[p..p+16). The unrolled implementation is larger than a simple loop, but
 * substantially faster.
 */
export function xorBlock(
  k: Uint32Array,
  n0: number,
  n1: number,
  n2: number,
  cnt: number,
  o: Uint32Array,
  p: number,
): void {
  const y04 = k[0],
    y05 = k[1],
    y06 = k[2],
    y07 = k[3],
    y08 = k[4],
    y09 = k[5],
    y10 = k[6],
    y11 = k[7];
  let x00 = 0x61707865,
    x01 = 0x3320646e,
    x02 = 0x79622d32,
    x03 = 0x6b206574,
    x04 = y04,
    x05 = y05,
    x06 = y06,
    x07 = y07,
    x08 = y08,
    x09 = y09,
    x10 = y10,
    x11 = y11,
    x12 = cnt,
    x13 = n0,
    x14 = n1,
    x15 = n2;
  for (let r = 0; r < 10; r++) {
    x00 = (x00 + x04) | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = (x08 + x12) | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = (x00 + x04) | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = (x08 + x12) | 0;
    x04 = rotl(x04 ^ x08, 7);

    x01 = (x01 + x05) | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = (x09 + x13) | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = (x01 + x05) | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = (x09 + x13) | 0;
    x05 = rotl(x05 ^ x09, 7);

    x02 = (x02 + x06) | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = (x10 + x14) | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = (x02 + x06) | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = (x10 + x14) | 0;
    x06 = rotl(x06 ^ x10, 7);

    x03 = (x03 + x07) | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = (x11 + x15) | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = (x03 + x07) | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = (x11 + x15) | 0;
    x07 = rotl(x07 ^ x11, 7);

    x00 = (x00 + x05) | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = (x10 + x15) | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = (x00 + x05) | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = (x10 + x15) | 0;
    x05 = rotl(x05 ^ x10, 7);

    x01 = (x01 + x06) | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = (x11 + x12) | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = (x01 + x06) | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = (x11 + x12) | 0;
    x06 = rotl(x06 ^ x11, 7);

    x02 = (x02 + x07) | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = (x08 + x13) | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = (x02 + x07) | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = (x08 + x13) | 0;
    x07 = rotl(x07 ^ x08, 7);

    x03 = (x03 + x04) | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = (x09 + x14) | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = (x03 + x04) | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = (x09 + x14) | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  o[p++] ^= x00 + 0x61707865;
  o[p++] ^= x01 + 0x3320646e;
  o[p++] ^= x02 + 0x79622d32;
  o[p++] ^= x03 + 0x6b206574;
  o[p++] ^= x04 + y04;
  o[p++] ^= x05 + y05;
  o[p++] ^= x06 + y06;
  o[p++] ^= x07 + y07;
  o[p++] ^= x08 + y08;
  o[p++] ^= x09 + y09;
  o[p++] ^= x10 + y10;
  o[p++] ^= x11 + y11;
  o[p++] ^= x12 + cnt;
  o[p++] ^= x13 + n0;
  o[p++] ^= x14 + n1;
  o[p] ^= x15 + n2;
}

/** RFC 8439 limit: 2^32 - 1 blocks of 64 bytes (counter starts at 1). */
const MAX_LEN = 2 ** 38 - 64;

/**
 * Shared AEAD body. `out` already holds the input of the stream cipher in
 * out[0..len). For decryption, `tag` is the received tag, and out[0..len) is
 * authenticated before it is decrypted in place.
 *
 * Every input byte is read exactly once (into `out` or into the Poly1305
 * state), so the bytes that are authenticated are the bytes that are
 * decrypted even if an input is backed by shared memory that another thread
 * modifies during the call.
 */
function run(
  k: Uint32Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  out: Uint8Array,
  len: number,
  tag?: Uint8Array,
): Uint8Array {
  if (!isLE) throw new Error("Non little-endian hardware is not supported");
  if (k.length !== 8) throw new Error("invalid key length");
  if (nonce.length !== 12) throw new Error("invalid nonce length");
  if (len > MAX_LEN) throw new Error("data too long");
  const n0 = le32(nonce, 0), n1 = le32(nonce, 4), n2 = le32(nonce, 8);
  const b = new Uint32Array(16);
  const b8 = new Uint8Array(b.buffer);
  try {
    if (tag) {
      xorBlock(k, n0, n1, n2, 0, b, 0);
      const expected = poly1305Tag(b8, aad, out, len);
      let diff = 0;
      for (let i = 0; i < 16; i++) diff |= expected[i] ^ tag[i];
      if (diff) throw new Error("invalid tag");
      b.fill(0);
    }
    const full = len - (len % 64);
    const o = new Uint32Array(out.buffer, 0, full / 4);
    let cnt = 1, pos = 0;
    for (; pos < full; pos += 64) xorBlock(k, n0, n1, n2, cnt++, o, pos / 4);
    if (pos < len) {
      b8.set(out.subarray(pos, len));
      xorBlock(k, n0, n1, n2, cnt, b, 0);
      out.set(b8.subarray(0, len - pos), pos);
      b.fill(0);
    }
    if (!tag) {
      xorBlock(k, n0, n1, n2, 0, b, 0);
      out.set(poly1305Tag(b8, aad, out, len), len);
    }
  } finally {
    b.fill(0);
  }
  return out;
}

/**
 * Converts a 32-byte key into the 8 little-endian words used by
 * {@link seal} and {@link open}. A key of any other length yields an empty
 * array, which seal()/open() reject.
 */
export function keyWords(key: Uint8Array): Uint32Array {
  return Uint32Array.from(
    { length: key.length === 32 ? 8 : 0 },
    (_, i) => le32(key, 4 * i),
  );
}

/**
 * AEAD_CHACHA20_POLY1305 encryption. Returns ciphertext || tag in a new
 * buffer. The inputs are only read and may be unaligned views.
 */
export function seal(
  k: Uint32Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  pt: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(pt.length + 16);
  out.set(pt);
  return run(k, nonce, aad, out, pt.length);
}

/**
 * AEAD_CHACHA20_POLY1305 decryption of ciphertext || tag. Returns the plaintext
 * in a new buffer, or throws if the tag does not match.
 */
export function open(
  k: Uint32Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  const len = ct.length - 16;
  if (len < 0) throw new Error("ciphertext too short");
  // Authenticate and decrypt the same private copy of the ciphertext, never
  // the caller's buffer, which may be shared memory.
  return run(k, nonce, aad, ct.slice(0, len), len, ct.subarray(len));
}
