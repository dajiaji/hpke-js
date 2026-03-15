import type { CborValue } from "./types.ts";

class Decoder {
  private _data: Uint8Array;
  private _pos: number;

  constructor(data: Uint8Array) {
    this._data = data;
    this._pos = 0;
  }

  get position(): number {
    return this._pos;
  }

  decode(): CborValue {
    if (this._pos >= this._data.length) {
      throw new Error("CBOR: unexpected end of input");
    }
    const initial = this._data[this._pos++];
    const major = initial >> 5;
    const additional = initial & 0x1f;

    switch (major) {
      case 0: // unsigned int
        return this._readUint(additional);
      case 1: // negative int
        return -1 - this._readUint(additional);
      case 2: // byte string
        return this._readBytes(this._readUint(additional));
      case 3: // text string
        return new TextDecoder().decode(
          this._readBytes(this._readUint(additional)),
        );
      case 4: // array
        return this._readArray(this._readUint(additional));
      case 5: // map
        return this._readMap(this._readUint(additional));
      case 6: // tag (skip tag number, return inner value)
        this._readUint(additional);
        return this.decode();
      case 7: // simple/float
        if (additional === 22) {
          return null;
        }
        throw new Error(`CBOR: unsupported simple value ${additional}`);
      default:
        throw new Error(`CBOR: unsupported major type ${major}`);
    }
  }

  private _readUint(additional: number): number {
    if (additional < 24) {
      return additional;
    }
    if (additional === 24) {
      return this._data[this._pos++];
    }
    if (additional === 25) {
      const val = (this._data[this._pos] << 8) | this._data[this._pos + 1];
      this._pos += 2;
      return val;
    }
    if (additional === 26) {
      const val = (this._data[this._pos] << 24) |
        (this._data[this._pos + 1] << 16) |
        (this._data[this._pos + 2] << 8) |
        this._data[this._pos + 3];
      this._pos += 4;
      return val >>> 0; // unsigned
    }
    if (additional === 27) {
      const dv = new DataView(
        this._data.buffer,
        this._data.byteOffset + this._pos,
        8,
      );
      const val = dv.getBigUint64(0);
      this._pos += 8;
      if (val > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error("CBOR: integer too large for number");
      }
      return Number(val);
    }
    throw new Error(`CBOR: unsupported additional info ${additional}`);
  }

  private _readBytes(len: number): Uint8Array {
    const slice = this._data.slice(this._pos, this._pos + len);
    this._pos += len;
    return slice;
  }

  private _readArray(len: number): CborValue[] {
    const arr: CborValue[] = [];
    for (let i = 0; i < len; i++) {
      arr.push(this.decode());
    }
    return arr;
  }

  private _readMap(len: number): Map<CborValue, CborValue> {
    const map = new Map<CborValue, CborValue>();
    for (let i = 0; i < len; i++) {
      const key = this.decode();
      const val = this.decode();
      map.set(key, val);
    }
    return map;
  }
}

/** Decode a CBOR byte string into a CborValue. */
export function decode(data: Uint8Array): CborValue {
  const decoder = new Decoder(data);
  const value = decoder.decode();
  if (decoder.position !== data.length) {
    throw new Error("CBOR: trailing bytes after decoded value");
  }
  return value;
}
