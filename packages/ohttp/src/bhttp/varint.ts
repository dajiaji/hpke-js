/**
 * QUIC variable-length integer encoding (RFC 9000 Section 16), used by
 * Binary HTTP (RFC 9292) for all length and integer fields.
 *
 * Values are limited to `Number.MAX_SAFE_INTEGER` since they are handled as
 * JavaScript numbers.
 *
 * @module
 */

import { OhttpError } from "../errors.ts";

const MAX_1 = 0x3f;
const MAX_2 = 0x3fff;
const MAX_4 = 0x3fffffff;
const TWO_POW_32 = 0x100000000;

/**
 * Returns the number of bytes needed to encode `v` as a varint.
 */
export function varintLength(v: number): 1 | 2 | 4 | 8 {
  if (!Number.isSafeInteger(v) || v < 0) {
    throw new OhttpError(`Invalid varint value: ${v}`);
  }
  if (v <= MAX_1) return 1;
  if (v <= MAX_2) return 2;
  if (v <= MAX_4) return 4;
  return 8;
}

/**
 * Writes `v` as a varint into `buf` at `offset`.
 *
 * @returns The offset just after the written varint.
 */
export function writeVarint(
  buf: Uint8Array,
  offset: number,
  v: number,
): number {
  switch (varintLength(v)) {
    case 1:
      buf[offset] = v;
      return offset + 1;
    case 2:
      buf[offset] = 0x40 | (v >>> 8);
      buf[offset + 1] = v & 0xff;
      return offset + 2;
    case 4:
      buf[offset] = 0x80 | (v >>> 24);
      buf[offset + 1] = (v >>> 16) & 0xff;
      buf[offset + 2] = (v >>> 8) & 0xff;
      buf[offset + 3] = v & 0xff;
      return offset + 4;
    default: {
      const hi = Math.floor(v / TWO_POW_32);
      const lo = v >>> 0;
      buf[offset] = 0xc0 | (hi >>> 24);
      buf[offset + 1] = (hi >>> 16) & 0xff;
      buf[offset + 2] = (hi >>> 8) & 0xff;
      buf[offset + 3] = hi & 0xff;
      buf[offset + 4] = lo >>> 24;
      buf[offset + 5] = (lo >>> 16) & 0xff;
      buf[offset + 6] = (lo >>> 8) & 0xff;
      buf[offset + 7] = lo & 0xff;
      return offset + 8;
    }
  }
}

/**
 * Encodes `v` as a varint.
 */
export function encodeVarint(v: number): Uint8Array {
  const buf = new Uint8Array(varintLength(v));
  writeVarint(buf, 0, v);
  return buf;
}

/**
 * Reads a varint from `buf` at `offset`.
 *
 * @returns A tuple of the decoded value and the offset just after it.
 */
export function readVarint(
  buf: Uint8Array,
  offset: number,
): [value: number, next: number] {
  if (offset >= buf.byteLength) {
    throw new OhttpError("Invalid binary HTTP message: truncated varint");
  }
  const len = 1 << (buf[offset] >>> 6);
  if (offset + len > buf.byteLength) {
    throw new OhttpError("Invalid binary HTTP message: truncated varint");
  }
  const first = buf[offset] & 0x3f;
  switch (len) {
    case 1:
      return [first, offset + 1];
    case 2:
      return [(first << 8) | buf[offset + 1], offset + 2];
    case 4:
      return [
        ((first << 24) | (buf[offset + 1] << 16) | (buf[offset + 2] << 8) |
          buf[offset + 3]) >>> 0,
        offset + 4,
      ];
    default: {
      const hi = ((first << 24) | (buf[offset + 1] << 16) |
        (buf[offset + 2] << 8) | buf[offset + 3]) >>> 0;
      const lo = ((buf[offset + 4] << 24) | (buf[offset + 5] << 16) |
        (buf[offset + 6] << 8) | buf[offset + 7]) >>> 0;
      const v = hi * TWO_POW_32 + lo;
      if (!Number.isSafeInteger(v)) {
        throw new OhttpError(
          "Invalid binary HTTP message: varint exceeds Number.MAX_SAFE_INTEGER",
        );
      }
      return [v, offset + 8];
    }
  }
}
