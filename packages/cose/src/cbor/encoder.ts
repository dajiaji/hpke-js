import type { CborValue } from "./types.ts";

function encodeHead(major: number, value: number): Uint8Array {
  const mt = major << 5;
  if (value < 24) {
    return new Uint8Array([mt | value]);
  }
  if (value < 0x100) {
    return new Uint8Array([mt | 24, value]);
  }
  if (value < 0x10000) {
    const buf = new Uint8Array(3);
    buf[0] = mt | 25;
    buf[1] = (value >> 8) & 0xff;
    buf[2] = value & 0xff;
    return buf;
  }
  if (value < 0x100000000) {
    const buf = new Uint8Array(5);
    buf[0] = mt | 26;
    buf[1] = (value >> 24) & 0xff;
    buf[2] = (value >> 16) & 0xff;
    buf[3] = (value >> 8) & 0xff;
    buf[4] = value & 0xff;
    return buf;
  }
  // 64-bit: use DataView for values > 32 bits
  const buf = new Uint8Array(9);
  buf[0] = mt | 27;
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(1, BigInt(value));
  return buf;
}

function encodeValue(value: CborValue): Uint8Array[] {
  if (value === null) {
    return [new Uint8Array([0xf6])]; // major 7, simple value 22
  }

  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("CBOR: float encoding is not supported");
    }
    if (value >= 0) {
      return [encodeHead(0, value)]; // major 0: unsigned int
    }
    // negative int: major 1, value = -1 - n
    return [encodeHead(1, -1 - value)];
  }

  if (typeof value === "string") {
    const encoded = new TextEncoder().encode(value);
    return [encodeHead(3, encoded.length), encoded]; // major 3: text string
  }

  if (value instanceof Uint8Array) {
    return [encodeHead(2, value.length), value]; // major 2: byte string
  }

  if (Array.isArray(value)) {
    const parts: Uint8Array[] = [encodeHead(4, value.length)]; // major 4: array
    for (const item of value) {
      parts.push(...encodeValue(item));
    }
    return parts;
  }

  if (value instanceof Map) {
    // COSE deterministic encoding: sort by encoded key bytes (lexicographic)
    const entries: { keyBytes: Uint8Array; valParts: Uint8Array[] }[] = [];
    for (const [k, v] of value) {
      const keyParts = encodeValue(k);
      const keyBytes = concat(keyParts);
      entries.push({ keyBytes, valParts: encodeValue(v) });
    }
    entries.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));

    const parts: Uint8Array[] = [encodeHead(5, entries.length)]; // major 5: map
    for (const entry of entries) {
      parts.push(entry.keyBytes);
      for (const vp of entry.valParts) {
        parts.push(vp);
      }
    }
    return parts;
  }

  throw new Error("CBOR: unsupported value type");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

function concat(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) {
    total += p.length;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    result.set(p, offset);
    offset += p.length;
  }
  return result;
}

/** Encode a CborValue into a CBOR byte string. */
export function encode(value: CborValue): Uint8Array {
  return concat(encodeValue(value));
}

/** Encode a CborValue wrapped in a CBOR tag (major type 6). */
export function encodeTagged(tag: number, value: CborValue): Uint8Array {
  return concat([encodeHead(6, tag), ...encodeValue(value)]);
}
