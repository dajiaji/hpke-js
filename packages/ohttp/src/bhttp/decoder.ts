/**
 * Binary HTTP (RFC 9292) decoder.
 *
 * Both known-length and indeterminate-length messages are supported,
 * including truncated messages (Section 3.8) and padding (Section 3.8).
 * Trailers and informational (1xx) responses are validated but discarded since
 * they cannot be expressed with the Fetch API `Request`/`Response` objects.
 *
 * @module
 */

import { OhttpError } from "../errors.ts";
import { readVarint } from "./varint.ts";

const FRAMING_KNOWN_LENGTH_REQUEST = 0;
const FRAMING_KNOWN_LENGTH_RESPONSE = 1;
const FRAMING_INDETERMINATE_LENGTH_REQUEST = 2;
const FRAMING_INDETERMINATE_LENGTH_RESPONSE = 3;

/** Status codes for which the Fetch API requires a null body. */
const NULL_BODY_STATUSES = [204, 205, 304];

function invalid(reason: string): OhttpError {
  return new OhttpError(`Invalid binary HTTP message: ${reason}`);
}

/**
 * Converts bytes to a ByteString (each byte maps to one code unit), which is
 * the representation used by Fetch API headers and methods.
 */
function bytesToByteString(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.byteLength; i++) {
    s += String.fromCharCode(b[i]);
  }
  return s;
}

/** Sequential reader over a byte buffer. */
class Reader {
  private _buf: Uint8Array;
  private _pos = 0;

  constructor(buf: Uint8Array) {
    this._buf = buf;
  }

  get atEnd(): boolean {
    return this._pos >= this._buf.byteLength;
  }

  varint(): number {
    const [v, next] = readVarint(this._buf, this._pos);
    this._pos = next;
    return v;
  }

  bytes(len: number): Uint8Array {
    if (len > this._buf.byteLength - this._pos) {
      throw invalid("truncated");
    }
    const b = this._buf.subarray(this._pos, this._pos + len);
    this._pos += len;
    return b;
  }

  /** Reads a varint length prefix followed by that many bytes. */
  lengthPrefixed(): Uint8Array {
    return this.bytes(this.varint());
  }

  /** Ensures all remaining bytes are zero padding. */
  checkPadding(): void {
    for (; this._pos < this._buf.byteLength; this._pos++) {
      if (this._buf[this._pos] !== 0) {
        throw invalid("non-zero padding");
      }
    }
  }
}

const SP = 0x20;
const HTAB = 0x09;

/** Non-alphanumeric `tchar` octets (RFC 9110 Section 5.6.2). */
const TCHAR_SYMBOLS = new Set(
  [..."!#$%&'*+-.^_`|~"].map((c) => c.charCodeAt(0)),
);

function isTchar(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || // DIGIT
    (c >= 0x41 && c <= 0x5a) || // uppercase ALPHA
    (c >= 0x61 && c <= 0x7a) || // lowercase ALPHA
    TCHAR_SYMBOLS.has(c);
}

/**
 * Validates a field name. RFC 9292 Section 3.6 applies the HTTP field name
 * rules (a `token`, RFC 9110 Section 5.1), so uppercase letters are allowed;
 * the HTTP/2 lowercase requirement does not apply to Binary HTTP.
 * Pseudo-fields (e.g. ":path") are rejected since the control data carries
 * that information and `Headers` cannot represent them.
 */
function validateFieldName(name: Uint8Array): void {
  if (name.byteLength === 0) {
    throw invalid("empty field name");
  }
  if (name[0] === 0x3a) {
    throw invalid("pseudo-field name is not allowed");
  }
  for (const c of name) {
    if (!isTchar(c)) {
      throw invalid("invalid character in field name");
    }
  }
}

/**
 * Validates a field value per RFC 9113 Section 8.2.1, which RFC 9292
 * Section 3.6 applies to field values: it must not contain
 * NUL, LF or CR, and must not start or end with SP or HTAB. Validation is
 * performed on the raw octets since `Headers` silently strips such
 * whitespace.
 */
function validateFieldValue(value: Uint8Array): void {
  const len = value.byteLength;
  if (len === 0) {
    return;
  }
  for (const i of [0, len - 1]) {
    if (value[i] === SP || value[i] === HTAB) {
      throw invalid("leading or trailing whitespace in field value");
    }
  }
  for (const c of value) {
    if (c === 0x00 || c === 0x0a || c === 0x0d) {
      throw invalid("invalid character in field value");
    }
  }
}

/**
 * Builds a `Headers` from field lines. Multiple `cookie` field lines are
 * concatenated with "; " (RFC 9113 Section 8.2.3, RFC 9292 Section 3.6)
 * instead of the ", " used by `Headers.append()`.
 */
class FieldSectionBuilder {
  private _headers = new Headers();
  private _cookies: string[] = [];

  add(name: Uint8Array, value: Uint8Array): void {
    validateFieldName(name);
    validateFieldValue(value);
    // Field names are case-insensitive (RFC 9110 Section 5.1).
    const n = bytesToByteString(name).toLowerCase();
    const v = bytesToByteString(value);
    if (n === "cookie") {
      this._cookies.push(v);
    } else {
      this._headers.append(n, v);
    }
  }

  build(): Headers {
    if (this._cookies.length > 0) {
      this._headers.set("cookie", this._cookies.join("; "));
    }
    return this._headers;
  }
}

/**
 * Reads a field section (header or trailer section).
 * A section omitted by truncation is treated as empty.
 */
function readFieldSection(r: Reader, knownLength: boolean): Headers {
  const fields = new FieldSectionBuilder();
  if (r.atEnd) {
    return fields.build();
  }
  if (knownLength) {
    const section = new Reader(r.lengthPrefixed());
    while (!section.atEnd) {
      fields.add(section.lengthPrefixed(), section.lengthPrefixed());
    }
    return fields.build();
  }
  // Indeterminate length: field lines terminated by a zero-length name.
  for (let nameLen = r.varint(); nameLen !== 0; nameLen = r.varint()) {
    fields.add(r.bytes(nameLen), r.lengthPrefixed());
  }
  return fields.build();
}

/**
 * Reads the content into a newly allocated buffer of exactly its size.
 * Content omitted by truncation is treated as empty.
 */
function readContent(r: Reader, knownLength: boolean): Uint8Array {
  if (r.atEnd) {
    return new Uint8Array(0);
  }
  if (knownLength) {
    return r.lengthPrefixed().slice();
  }
  // Indeterminate length: chunks terminated by a zero-length chunk.
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (let len = r.varint(); len !== 0; len = r.varint()) {
    chunks.push(r.bytes(len));
    total += len;
  }
  const content = new Uint8Array(total);
  let p = 0;
  for (const chunk of chunks) {
    content.set(chunk, p);
    p += chunk.byteLength;
  }
  return content;
}

/** Reads content, trailers and padding that follow the header section. */
function readRemainder(r: Reader, knownLength: boolean): Uint8Array {
  const content = readContent(r, knownLength);
  readFieldSection(r, knownLength); // trailers are discarded
  r.checkPadding();
  return content;
}

/** Wraps non-OhttpError exceptions (e.g. TypeError from Fetch API objects). */
function wrapError(e: unknown): OhttpError {
  if (e instanceof OhttpError) {
    return e;
  }
  return invalid(e instanceof Error ? e.message : String(e));
}

/**
 * Decodes a Binary HTTP request into a `Request`.
 */
export function decodeRequest(src: Uint8Array): Request {
  try {
    const r = new Reader(src);
    const framing = r.varint();
    if (
      framing !== FRAMING_KNOWN_LENGTH_REQUEST &&
      framing !== FRAMING_INDETERMINATE_LENGTH_REQUEST
    ) {
      throw invalid(`unexpected framing indicator ${framing}`);
    }
    const knownLength = framing === FRAMING_KNOWN_LENGTH_REQUEST;

    // Request control data
    const method = bytesToByteString(r.lengthPrefixed());
    const scheme = bytesToByteString(r.lengthPrefixed());
    let authority = bytesToByteString(r.lengthPrefixed());
    const path = bytesToByteString(r.lengthPrefixed());

    const headers = readFieldSection(r, knownLength);
    const content = readRemainder(r, knownLength);

    if (authority === "") {
      authority = headers.get("host") ?? "";
    }
    if (scheme === "" || authority === "") {
      throw invalid("missing scheme or authority");
    }
    const hasNoBody = method === "GET" || method === "HEAD";
    if (hasNoBody && content.byteLength > 0) {
      throw invalid(`${method} request with content is not supported`);
    }
    return new Request(`${scheme}://${authority}${path}`, {
      method,
      headers,
      body: hasNoBody || content.byteLength === 0
        ? null
        : content.buffer as ArrayBuffer,
    });
  } catch (e: unknown) {
    throw wrapError(e);
  }
}

/**
 * Decodes a Binary HTTP response into a `Response`.
 */
export function decodeResponse(src: Uint8Array): Response {
  try {
    const r = new Reader(src);
    const framing = r.varint();
    if (
      framing !== FRAMING_KNOWN_LENGTH_RESPONSE &&
      framing !== FRAMING_INDETERMINATE_LENGTH_RESPONSE
    ) {
      throw invalid(`unexpected framing indicator ${framing}`);
    }
    const knownLength = framing === FRAMING_KNOWN_LENGTH_RESPONSE;

    // Informational responses (discarded) followed by the final status.
    let status = r.varint();
    while (status >= 100 && status < 200) {
      readFieldSection(r, knownLength);
      status = r.varint();
    }
    if (status < 200 || status > 599) {
      throw invalid(`invalid status code ${status}`);
    }

    const headers = readFieldSection(r, knownLength);
    const content = readRemainder(r, knownLength);

    const nullBody = NULL_BODY_STATUSES.includes(status);
    if (nullBody && content.byteLength > 0) {
      throw invalid(`status ${status} response with content`);
    }
    return new Response(nullBody ? null : content.buffer as ArrayBuffer, {
      status,
      headers,
    });
  } catch (e: unknown) {
    throw wrapError(e);
  }
}
