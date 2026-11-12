// RFC 9292 Web Streams adapter. Kept out of the low-level entry point.
import { OhttpError } from "./errors.ts";
import {
  ByteReader,
  concat,
  encodeInteger,
  fragments,
  stream,
} from "./streams.ts";

const MAX_FIELDS_SIZE = 65536;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "transfer-encoding",
  "upgrade",
]);

// Normalize data validation errors only at the Web API calls that validate
// untrusted values. TypeErrors from our parsing or cryptographic code propagate.
function parseValue<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error) {
    if (error instanceof TypeError) {
      throw new OhttpError("Invalid binary HTTP value: " + error.message);
    }
    throw error;
  }
}

function string(value: string): Uint8Array {
  const bytes = textEncoder.encode(value);
  return concat([encodeInteger(bytes.length), bytes]);
}

function fields(headers: Headers): Uint8Array {
  const parts: Uint8Array[] = [];
  const excluded = new Set(HOP_BY_HOP);
  for (const name of (headers.get("connection") ?? "").split(",")) {
    if (name.trim()) excluded.add(name.trim().toLowerCase());
  }
  headers.forEach((value, name) => {
    if (excluded.has(name)) return;
    parts.push(string(name), string(value));
  });
  parts.push(encodeInteger(0));
  const result = concat(parts);
  if (result.length > MAX_FIELDS_SIZE) {
    throw new OhttpError("Binary HTTP fields too large");
  }
  return result;
}

/** Encode indeterminate-length binary HTTP without buffering the body. */
export function encodeRequest(request: Request): ReadableStream<Uint8Array> {
  const url = new URL(request.url);
  const control = concat([
    encodeInteger(2),
    string(request.method),
    string(url.protocol.slice(0, -1)),
    string(url.host),
    string(url.pathname + url.search),
    fields(request.headers),
  ]);
  return encode(control, request.body);
}

export function encodeResponse(response: Response): ReadableStream<Uint8Array> {
  return encode(
    concat([
      encodeInteger(3),
      encodeInteger(response.status),
      fields(response.headers),
    ]),
    response.body,
  );
}

function encode(
  control: Uint8Array,
  body: ReadableStream<Uint8Array> | null,
): ReadableStream<Uint8Array> {
  const reader = body ? new ByteReader(body) : undefined;
  return stream(
    (async function* () {
      yield control;
      if (reader) {
        for await (const bytes of reader.rest()) {
          if (!bytes.length) continue;
          yield concat([encodeInteger(bytes.length), bytes]);
        }
      }
      yield new Uint8Array([0, 0]); // content and trailer terminators
    })(),
    () => reader?.close() ?? Promise.resolve(),
  );
}

async function integer(reader: ByteReader): Promise<number> {
  return (await reader.integer())!;
}

async function readString(reader: ByteReader, size?: number): Promise<string> {
  const length = size ?? await integer(reader);
  if (length > MAX_FIELDS_SIZE) {
    throw new OhttpError("Binary HTTP field too large");
  }
  const bytes = await reader.read(length);
  return parseValue(() => textDecoder.decode(bytes));
}

async function readFields(
  reader: ByteReader,
  indeterminate: boolean,
  optional = false,
): Promise<Headers> {
  const result = new Headers();
  const sectionLength = indeterminate
    ? undefined
    : await reader.integer(optional);
  if (!indeterminate && sectionLength === undefined) return result;
  if (sectionLength !== undefined && sectionLength > MAX_FIELDS_SIZE) {
    throw new OhttpError("Binary HTTP fields too large");
  }
  // Known-length sections are small, independently bounded buffers.
  const section = indeterminate
    ? reader
    : new ByteReader([await reader.read(sectionLength!)]);
  const start = section.position;
  try {
    for (;;) {
      const length = await section.integer(!indeterminate || optional);
      if (length === undefined || (indeterminate && length === 0)) break;
      if (!length) throw new OhttpError("Empty binary HTTP field name");
      const name = await readString(section, length);
      const value = await readString(section);
      if (section.position - start > MAX_FIELDS_SIZE) {
        throw new OhttpError("Binary HTTP fields too large");
      }
      if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || HOP_BY_HOP.has(name)) {
        throw new OhttpError("Invalid binary HTTP field name");
      }
      parseValue(() => result.append(name, value));
      optional = false;
    }
    return result;
  } finally {
    if (!indeterminate) await section.close();
  }
}

function bodyStream(
  reader: ByteReader,
  indeterminate: boolean,
  onError?: (error: unknown) => void,
): ReadableStream<Uint8Array> {
  return stream(
    (async function* () {
      try {
        let length = await reader.integer(true);
        if (length !== undefined) {
          for (;;) {
            if (length === 0) break;
            while (length > 0) {
              const part = await reader.piece(Math.min(length, 16384));
              if (!part.length) {
                throw new OhttpError(
                  "Truncated binary HTTP content",
                );
              }
              length -= part.length;
              yield part;
            }
            if (!indeterminate) break;
            length = await integer(reader);
          }
          await readFields(reader, indeterminate, true); // Web Fetch does not expose trailers.
        }
        for await (const padding of reader.rest()) {
          if (padding.some((b) => b !== 0)) {
            throw new OhttpError(
              "Invalid binary HTTP padding",
            );
          }
        }
      } catch (error) {
        onError?.(error);
        throw error;
      } finally {
        await reader.close();
      }
    })(),
    () => reader.close(),
  );
}

async function drainEmpty(body: ReadableStream<Uint8Array>): Promise<void> {
  for await (const part of fragments(body)) {
    if (part.length) throw new OhttpError("Unexpected binary HTTP body");
  }
}

/** Parse control data and headers now; parse content/trailers as the body is read. */
export async function decodeRequest(
  source: ReadableStream<Uint8Array>,
  onBodyError?: (error: unknown) => void,
): Promise<Request> {
  const reader = new ByteReader(source);
  try {
    const framing = await integer(reader);
    if (framing !== 0 && framing !== 2) {
      throw new OhttpError("Invalid binary HTTP request framing");
    }
    const method = await readString(reader);
    const scheme = await readString(reader);
    const authority = await readString(reader);
    const path = await readString(reader);
    const headers = await readFields(reader, framing === 2, true);
    const targetAuthority = authority || headers.get("host") || "";
    if (
      !/^https?$/i.test(scheme) ||
      !targetAuthority || /[\s/\\?#@]/.test(targetAuthority) ||
      !path.startsWith("/") || /[\\#]/.test(path) ||
      Array.from(path).some((c) =>
        c.charCodeAt(0) <= 32 || c.charCodeAt(0) === 127
      )
    ) {
      throw new OhttpError("Invalid binary HTTP authority or path");
    }
    const body = bodyStream(reader, framing === 2, onBodyError);
    const url = parseValue(() =>
      new URL(
        scheme + "://" + targetAuthority + path,
      )
    );
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new OhttpError("Unsupported target scheme");
    }
    if (method === "GET" || method === "HEAD") {
      await drainEmpty(body);
      return parseValue(() => new Request(url, { method, headers }));
    }
    return parseValue(() =>
      new Request(
        url,
        { method, headers, body, duplex: "half" } as RequestInit,
      )
    );
  } catch (error) {
    await reader.close();
    throw error;
  }
}

export async function decodeResponse(
  source: ReadableStream<Uint8Array>,
  method = "GET",
): Promise<Response> {
  const reader = new ByteReader(source);
  try {
    const framing = await integer(reader);
    if (framing !== 1 && framing !== 3) {
      throw new OhttpError("Invalid binary HTTP response framing");
    }
    let status: number;
    let headers: Headers;
    do {
      status = await integer(reader);
      if (status < 100 || status > 599 || status === 101) {
        throw new OhttpError("Invalid binary HTTP status");
      }
      headers = await readFields(reader, framing === 3, true);
    } while (status < 200);
    const body = bodyStream(reader, framing === 3);
    if (
      method === "HEAD" || status === 204 || status === 205 || status === 304
    ) {
      await drainEmpty(body);
      return new Response(null, { status, headers });
    }
    return new Response(body, { status, headers });
  } catch (error) {
    await reader.close();
    throw error;
  }
}
