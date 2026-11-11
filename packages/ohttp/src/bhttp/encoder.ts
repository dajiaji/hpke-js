/**
 * Binary HTTP (RFC 9292) encoder.
 *
 * Messages are always encoded in the known-length format without padding.
 * Trailers and informational responses cannot be expressed with the Fetch API
 * `Request`/`Response` objects and are therefore never emitted.
 *
 * @module
 */

import { OhttpError } from "../errors.ts";
import { varintLength, writeVarint } from "./varint.ts";

const FRAMING_KNOWN_LENGTH_REQUEST = 0;
const FRAMING_KNOWN_LENGTH_RESPONSE = 1;

/** Accumulates byte chunks and serializes them into a single buffer. */
class Writer {
  private _parts: (number | Uint8Array)[] = [];
  private _length = 0;

  varint(v: number): this {
    this._parts.push(v);
    this._length += varintLength(v);
    return this;
  }

  /** Writes a varint length prefix followed by `bytes`. */
  lengthPrefixed(bytes: Uint8Array): this {
    this.varint(bytes.byteLength);
    this._parts.push(bytes);
    this._length += bytes.byteLength;
    return this;
  }

  finish(): Uint8Array {
    const out = new Uint8Array(this._length);
    let p = 0;
    for (const part of this._parts) {
      if (typeof part === "number") {
        p = writeVarint(out, p, part);
      } else {
        out.set(part, p);
        p += part.byteLength;
      }
    }
    return out;
  }
}

/**
 * Converts a ByteString (as used by Fetch API headers, methods and
 * serialized URL components) to bytes. Each code unit maps to one byte.
 */
function byteStringToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0xff) {
      throw new OhttpError(`Invalid ByteString: ${JSON.stringify(s)}`);
    }
    out[i] = c;
  }
  return out;
}

/** Encodes a field section (headers) as a series of field lines. */
function encodeFieldSection(headers: Headers): Uint8Array {
  const w = new Writer();
  headers.forEach((value, name) => {
    w.lengthPrefixed(byteStringToBytes(name));
    w.lengthPrefixed(byteStringToBytes(value));
  });
  return w.finish();
}

/**
 * Encodes a `Request` as a known-length Binary HTTP request.
 */
export async function encodeRequest(request: Request): Promise<Uint8Array> {
  const url = new URL(request.url);
  const content = new Uint8Array(await request.arrayBuffer());
  return new Writer()
    .varint(FRAMING_KNOWN_LENGTH_REQUEST)
    // Request control data
    .lengthPrefixed(byteStringToBytes(request.method))
    .lengthPrefixed(byteStringToBytes(url.protocol.slice(0, -1)))
    .lengthPrefixed(byteStringToBytes(url.host))
    .lengthPrefixed(byteStringToBytes(url.pathname + url.search))
    // Known-length field section, content and (empty) trailer section
    .lengthPrefixed(encodeFieldSection(request.headers))
    .lengthPrefixed(content)
    .varint(0)
    .finish();
}

/**
 * Encodes a `Response` as a known-length Binary HTTP response.
 */
export async function encodeResponse(response: Response): Promise<Uint8Array> {
  const status = response.status;
  if (status < 200 || status > 599) {
    throw new OhttpError(`Unsupported response status: ${status}`);
  }
  const content = new Uint8Array(await response.arrayBuffer());
  return new Writer()
    .varint(FRAMING_KNOWN_LENGTH_RESPONSE)
    // Final response control data
    .varint(status)
    // Known-length field section, content and (empty) trailer section
    .lengthPrefixed(encodeFieldSection(response.headers))
    .lengthPrefixed(content)
    .varint(0)
    .finish();
}
