import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { decodeRequest, decodeResponse } from "../src/bhttp/decoder.ts";
import { encodeRequest, encodeResponse } from "../src/bhttp/encoder.ts";
import { encodeVarint, readVarint, varintLength } from "../src/bhttp/varint.ts";
import { OhttpError } from "../src/errors.ts";
import { bytesToHex, hexToBytes } from "./utils.ts";

const te = new TextEncoder();

/** Concatenates byte sequences, varints (numbers) and ASCII strings. */
function bin(...parts: (number | string | Uint8Array)[]): Uint8Array {
  const chunks = parts.map((p) =>
    typeof p === "number"
      ? encodeVarint(p)
      : typeof p === "string"
      ? te.encode(p)
      : p
  );
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** Length-prefixed ASCII string. */
function lp(s: string | Uint8Array): Uint8Array {
  const b = typeof s === "string" ? te.encode(s) : s;
  return bin(b.byteLength, b);
}

/** Known-length field section. */
function kfs(...fields: [string, string][]): Uint8Array {
  return lp(bin(...fields.flatMap(([n, v]) => [lp(n), lp(v)])));
}

/** Indeterminate-length field section. */
function ifs(...fields: [string, string][]): Uint8Array {
  return bin(...fields.flatMap(([n, v]) => [lp(n), lp(v)]), 0);
}

const UA = "curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3";

// RFC 9292 Section 5.1 (known-length encoding).
const RFC9292_KNOWN_LENGTH_REQUEST = `
  00034745 54056874 74707300 0a2f6865 6c6c6f2e 74787440 6c0a7573 65722d61
  67656e74 34637572 6c2f372e 31362e33 206c6962 6375726c 2f372e31 362e3320
  4f70656e 53534c2f 302e392e 376c207a 6c69622f 312e322e 3304686f 73740f77
  77772e65 78616d70 6c652e63 6f6d0f61 63636570 742d6c61 6e677561 67650665
  6e2c206d 690000`;

// RFC 9292 Section 5.1 (indeterminate-length encoding with padding).
const RFC9292_INDETERMINATE_LENGTH_REQUEST = `
  02034745 54056874 74707300 0a2f6865 6c6c6f2e 7478740a 75736572 2d616765
  6e743463 75726c2f 372e3136 2e33206c 69626375 726c2f37 2e31362e 33204f70
  656e5353 4c2f302e 392e376c 207a6c69 622f312e 322e3304 686f7374 0f777777
  2e657861 6d706c65 2e636f6d 0f616363 6570742d 6c616e67 75616765 06656e2c
  206d6900 00000000 00000000 00000000`;

// RFC 9292 Section 5.2 (indeterminate-length response with
// informational responses and chunked content).
const RFC9292_CONTENT = "Hello World! My content includes a trailing CRLF.\r\n";
const RFC9292_FINAL_HEADERS: [string, string][] = [
  ["date", "Mon, 27 Jul 2009 12:28:53 GMT"],
  ["server", "Apache"],
  ["last-modified", "Wed, 22 Jul 2009 19:15:56 GMT"],
  ["etag", '"34aa387-d-1568eb00"'],
  ["accept-ranges", "bytes"],
  ["content-length", "51"],
  ["vary", "Accept-Encoding"],
  ["content-type", "text/plain"],
];
const RFC9292_INDETERMINATE_LENGTH_RESPONSE = bin(
  3,
  102,
  ifs(["running", '"sleep 15"']),
  103,
  ifs(
    ["link", "</style.css>; rel=preload; as=style"],
    ["link", "</script.js>; rel=preload; as=script"],
  ),
  200,
  ifs(...RFC9292_FINAL_HEADERS),
  lp(RFC9292_CONTENT),
  0, // end of content
  0, // empty trailers
);

function assertInvalid(
  f: () => unknown,
  msgIncludes?: string,
  msg?: string,
): void {
  assertThrows(f, OhttpError, msgIncludes, msg);
}

describe("varint", () => {
  it("should decode RFC 9000 Appendix A.1 examples", () => {
    assertEquals(readVarint(hexToBytes("9d7f3e7d"), 0), [494878333, 4]);
    assertEquals(readVarint(hexToBytes("7bbd"), 0), [15293, 2]);
    assertEquals(readVarint(hexToBytes("25"), 0), [37, 1]);
    // Non-minimal encodings are allowed.
    assertEquals(readVarint(hexToBytes("4025"), 0), [37, 2]);
    // 151288809941952652 exceeds Number.MAX_SAFE_INTEGER.
    assertInvalid(
      () => readVarint(hexToBytes("c2197c5eff14e88c"), 0),
      "MAX_SAFE_INTEGER",
    );
  });

  it("should encode RFC 9000 Appendix A.1 examples", () => {
    assertEquals(bytesToHex(encodeVarint(494878333)), "9d7f3e7d");
    assertEquals(bytesToHex(encodeVarint(15293)), "7bbd");
    assertEquals(bytesToHex(encodeVarint(37)), "25");
  });

  it("should round-trip boundary values with minimal length", () => {
    const cases: [number, number][] = [
      [0, 1],
      [63, 1],
      [64, 2],
      [16383, 2],
      [16384, 4],
      [1073741823, 4],
      [1073741824, 8],
      [2 ** 32, 8],
      [Number.MAX_SAFE_INTEGER, 8],
    ];
    for (const [v, len] of cases) {
      const enc = encodeVarint(v);
      assertEquals(enc.byteLength, len, `length of ${v}`);
      assertEquals(varintLength(v), len);
      assertEquals(readVarint(enc, 0), [v, len], `value ${v}`);
    }
    assertEquals(
      bytesToHex(encodeVarint(Number.MAX_SAFE_INTEGER)),
      "c01fffffffffffff",
    );
  });

  it("should read at an offset", () => {
    assertEquals(readVarint(hexToBytes("ff7bbd25"), 1), [15293, 3]);
  });

  it("should reject invalid values", () => {
    for (const v of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity]) {
      assertInvalid(() => encodeVarint(v), "Invalid varint");
    }
  });

  it("should reject truncated input", () => {
    assertInvalid(() => readVarint(new Uint8Array(0), 0), "truncated");
    assertInvalid(() => readVarint(hexToBytes("40"), 0), "truncated");
    assertInvalid(() => readVarint(hexToBytes("9d7f3e"), 0), "truncated");
    assertInvalid(() => readVarint(hexToBytes("c0000000"), 0), "truncated");
  });
});

describe("decodeRequest", () => {
  it("should decode the RFC 9292 known-length request", () => {
    const req = decodeRequest(hexToBytes(RFC9292_KNOWN_LENGTH_REQUEST));
    assertEquals(req.method, "GET");
    // The empty authority is taken from the Host header.
    assertEquals(req.url, "https://www.example.com/hello.txt");
    assertEquals(req.headers.get("user-agent"), UA);
    assertEquals(req.headers.get("accept-language"), "en, mi");
  });

  it("should decode the RFC 9292 indeterminate-length request with padding", () => {
    const req = decodeRequest(
      hexToBytes(RFC9292_INDETERMINATE_LENGTH_REQUEST),
    );
    assertEquals(req.method, "GET");
    assertEquals(req.url, "https://www.example.com/hello.txt");
    assertEquals(req.headers.get("user-agent"), UA);
    assertEquals(req.headers.get("accept-language"), "en, mi");
  });

  it("should prefer the authority in the control data over Host", () => {
    const req = decodeRequest(
      bin(
        0,
        lp("GET"),
        lp("https"),
        lp("a.example"),
        lp("/"),
        kfs([
          "host",
          "b.example",
        ]),
      ),
    );
    assertEquals(req.url, "https://a.example/");
  });

  it("should decode a known-length POST request with content", async () => {
    const req = decodeRequest(
      bin(
        0,
        lp("POST"),
        lp("https"),
        lp("example.com"),
        lp("/submit?x=1"),
        kfs(["content-type", "text/plain"]),
        lp("Hello world!"),
        0,
      ),
    );
    assertEquals(req.method, "POST");
    assertEquals(req.url, "https://example.com/submit?x=1");
    assertEquals(req.headers.get("content-type"), "text/plain");
    assertEquals(await req.text(), "Hello world!");
  });

  it("should decode chunked indeterminate-length content", async () => {
    const req = decodeRequest(
      bin(
        2,
        lp("PUT"),
        lp("https"),
        lp("example.com"),
        lp("/"),
        ifs(),
        lp("Hello"),
        lp(", "),
        lp("world!"),
        0,
        0,
      ),
    );
    assertEquals(await req.text(), "Hello, world!");
  });

  it("should handle field names longer than 63 bytes (2-byte varint)", () => {
    const name = "x-" + "a".repeat(100);
    const value = "v".repeat(200);
    for (const framing of [0, 2]) {
      const fs = framing === 0 ? kfs([name, value]) : ifs([name, value]);
      const req = decodeRequest(
        bin(framing, lp("GET"), lp("https"), lp("example.com"), lp("/"), fs),
      );
      assertEquals(req.headers.get(name), value);
    }
  });

  it("should keep repeated fields", () => {
    const req = decodeRequest(
      bin(
        0,
        lp("GET"),
        lp("https"),
        lp("example.com"),
        lp("/"),
        kfs(["accept", "text/html"], ["accept", "text/plain"]),
      ),
    );
    assertEquals(req.headers.get("accept"), "text/html, text/plain");
  });

  it("should concatenate repeated Cookie fields with '; '", () => {
    for (const framing of [0, 2]) {
      const fields: [string, string][] = [
        ["cookie", "a=1"],
        ["x-a", "1"],
        ["cookie", "b=2"],
      ];
      const req = decodeRequest(
        bin(
          framing,
          lp("GET"),
          lp("https"),
          lp("example.com"),
          lp("/"),
          framing === 0 ? kfs(...fields) : ifs(...fields),
        ),
      );
      assertEquals(req.headers.get("cookie"), "a=1; b=2");
      assertEquals(req.headers.get("x-a"), "1");
    }
  });

  it("should accept field names with uppercase letters and all tchars", async () => {
    const tcharName = "!#$%&'*+-.^_`|~0123456789ABCXYZabcxyz";
    for (const framing of [0, 2]) {
      const fields: [string, string][] = [
        ["Content-Type", "text/plain"],
        ["X-Custom", "1"],
        [tcharName, "2"],
        ["Cookie", "a=1"],
        ["COOKIE", "b=2"],
      ];
      const req = decodeRequest(
        bin(
          framing,
          lp("POST"),
          lp("https"),
          lp("example.com"),
          lp("/"),
          framing === 0 ? kfs(...fields) : ifs(...fields),
          framing === 0 ? lp("x") : bin(lp("x"), 0),
        ),
      );
      assertEquals(req.headers.get("content-type"), "text/plain");
      assertEquals(req.headers.get("x-custom"), "1");
      assertEquals(req.headers.get(tcharName), "2");
      // Cookie detection is case-insensitive.
      assertEquals(req.headers.get("cookie"), "a=1; b=2");
      assertEquals(await req.text(), "x");
    }
    const res = decodeResponse(
      bin(1, 103, kfs(["Link", "</a>"]), 200, kfs(["Set-Cookie", "a=1"])),
    );
    assertEquals(res.headers.getSetCookie(), ["a=1"]);
  });

  it("should accept and discard trailers", async () => {
    for (const framing of [0, 2]) {
      const known = framing === 0;
      const req = decodeRequest(
        bin(
          framing,
          lp("POST"),
          lp("https"),
          lp("example.com"),
          lp("/"),
          known ? kfs() : ifs(),
          known ? lp("abc") : bin(lp("abc"), 0),
          known ? kfs(["x-trailer", "1"]) : ifs(["x-trailer", "1"]),
        ),
      );
      assertEquals(req.headers.get("x-trailer"), null);
      assertEquals(await req.text(), "abc");
    }
  });

  it("should accept messages truncated at section boundaries", async () => {
    const control = bin(
      0,
      lp("POST"),
      lp("https"),
      lp("example.com"),
      lp("/"),
    );
    const withHeaders = bin(control, kfs(["x-a", "1"]));
    const withContent = bin(withHeaders, lp("abc"));
    for (const msg of [control, withHeaders, withContent]) {
      const req = decodeRequest(msg);
      assertEquals(req.url, "https://example.com/");
    }
    assertEquals(decodeRequest(withHeaders).headers.get("x-a"), "1");
    assertEquals(await decodeRequest(withContent).text(), "abc");
  });

  it("should decode Latin-1 field values byte by byte", () => {
    const raw = bin(
      0,
      lp("GET"),
      lp("https"),
      lp("example.com"),
      lp("/"),
      lp(bin(lp("x-latin1"), lp(new Uint8Array([0x63, 0x61, 0x66, 0xe9])))),
    );
    assertEquals(decodeRequest(raw).headers.get("x-latin1"), "café");
  });

  it("should reject invalid framing indicators", () => {
    for (const framing of [1, 3, 4, 64]) {
      assertInvalid(
        () =>
          decodeRequest(
            bin(framing, lp("GET"), lp("https"), lp("example.com"), lp("/")),
          ),
        "framing indicator",
      );
    }
  });

  it("should reject truncated control data", () => {
    const full = bin(0, lp("GET"), lp("https"), lp("example.com"), lp("/"));
    for (let len = 0; len < full.byteLength; len++) {
      assertInvalid(() => decodeRequest(full.slice(0, len)));
    }
  });

  it("should reject messages truncated inside a section", () => {
    const control = bin(
      0,
      lp("POST"),
      lp("https"),
      lp("example.com"),
      lp("/"),
    );
    // Field section length exceeds the remaining bytes.
    assertInvalid(() => decodeRequest(bin(control, 10, "abc")), "truncated");
    // Field line with a missing value.
    assertInvalid(
      () => decodeRequest(bin(control, lp(lp("x-a")))),
      "truncated",
    );
    // Content shorter than its length.
    assertInvalid(
      () => decodeRequest(bin(control, kfs(), 5, "ab")),
      "truncated",
    );
    // Indeterminate field section without terminator.
    assertInvalid(
      () =>
        decodeRequest(
          bin(2, lp("GET"), lp("https"), lp("example.com"), lp("/"), lp("x")),
        ),
      "truncated",
    );
  });

  it("should reject non-zero padding", () => {
    assertInvalid(
      () =>
        decodeRequest(
          bin(
            0,
            lp("GET"),
            lp("https"),
            lp("example.com"),
            lp("/"),
            kfs(),
            0,
            0,
            new Uint8Array([0, 0, 1]),
          ),
        ),
      "padding",
    );
  });

  it("should reject an empty field name", () => {
    assertInvalid(
      () =>
        decodeRequest(
          bin(
            0,
            lp("GET"),
            lp("https"),
            lp("example.com"),
            lp("/"),
            lp(bin(lp(""), lp("v"))),
          ),
        ),
      "empty field name",
    );
  });

  it("should reject invalid field names", () => {
    const names = [
      ":path", // pseudo-field
      ":foo", // unknown pseudo-field
      "x:a", // non-tchar delimiter
      "x(a)", // non-tchar delimiter
      'x"a', // DQUOTE
      "x a", // SP
      "x\ta", // HTAB
      "x\x00a", // NUL
      "x\x7fa", // DEL
      "x\u00e9", // non-ASCII
    ];
    for (const name of names) {
      const raw = new Uint8Array([...name].map((c) => c.charCodeAt(0)));
      for (const framing of [0, 2]) {
        const fs = framing === 0
          ? lp(bin(lp(raw), lp("v")))
          : bin(lp(raw), lp("v"), 0);
        assertInvalid(
          () =>
            decodeRequest(
              bin(
                framing,
                lp("GET"),
                lp("https"),
                lp("example.com"),
                lp("/"),
                fs,
              ),
            ),
          "field name",
          JSON.stringify(name),
        );
      }
    }
    // Also applies to trailers and informational responses.
    assertInvalid(
      () => decodeResponse(bin(1, 200, kfs(), lp(""), kfs(["x a", "1"]))),
      "field name",
    );
    assertInvalid(
      () => decodeResponse(bin(1, 103, kfs(["x a", "1"]), 200, kfs())),
      "field name",
    );
  });

  it("should reject invalid field values without normalizing them", () => {
    const cases: [string, string][] = [
      [" value", "whitespace"],
      ["value ", "whitespace"],
      ["\tvalue", "whitespace"],
      ["value\t", "whitespace"],
      [" value ", "whitespace"],
      [" ", "whitespace"],
      ["a\x00b", "invalid character"],
      ["a\nb", "invalid character"],
      ["a\rb", "invalid character"],
    ];
    for (const [value, msg] of cases) {
      for (const framing of [0, 2]) {
        const fs = framing === 0 ? kfs(["x-a", value]) : ifs(["x-a", value]);
        assertInvalid(
          () =>
            decodeRequest(
              bin(
                framing,
                lp("GET"),
                lp("https"),
                lp("example.com"),
                lp("/"),
                fs,
              ),
            ),
          msg,
        );
      }
    }
    // Interior whitespace, empty values and obs-text are allowed.
    const req = decodeRequest(
      bin(
        0,
        lp("GET"),
        lp("https"),
        lp("example.com"),
        lp("/"),
        kfs(["x-a", "a \t b"], ["x-b", ""]),
      ),
    );
    assertEquals(req.headers.get("x-a"), "a \t b");
    assertEquals(req.headers.get("x-b"), "");
  });

  it("should reject a missing authority", () => {
    assertInvalid(
      () => decodeRequest(bin(0, lp("GET"), lp("https"), lp(""), lp("/"))),
      "authority",
    );
    assertInvalid(
      () =>
        decodeRequest(bin(0, lp("GET"), lp(""), lp("example.com"), lp("/"))),
      "scheme",
    );
  });

  it("should reject GET/HEAD requests with content", () => {
    for (const method of ["GET", "HEAD"]) {
      assertInvalid(
        () =>
          decodeRequest(
            bin(
              0,
              lp(method),
              lp("https"),
              lp("example.com"),
              lp("/"),
              kfs(),
              lp("x"),
            ),
          ),
        "content",
      );
    }
  });

  it("should wrap Fetch API errors in OhttpError", () => {
    // Invalid header name.
    assertInvalid(() =>
      decodeRequest(
        bin(
          0,
          lp("GET"),
          lp("https"),
          lp("example.com"),
          lp("/"),
          kfs(["bad name", "v"]),
        ),
      )
    );
    // Invalid method token.
    assertInvalid(() =>
      decodeRequest(bin(0, lp("G T"), lp("https"), lp("example.com"), lp("/")))
    );
    // Invalid URL.
    assertInvalid(() =>
      decodeRequest(bin(0, lp("GET"), lp("https"), lp("exa mple"), lp("/")))
    );
  });
});

describe("decodeResponse", () => {
  it("should decode the RFC 9292 indeterminate-length response", async () => {
    const res = decodeResponse(RFC9292_INDETERMINATE_LENGTH_RESPONSE);
    assertEquals(res.status, 200);
    for (const [name, value] of RFC9292_FINAL_HEADERS) {
      assertEquals(res.headers.get(name), value);
    }
    // Informational response fields must not leak into the final response.
    assertEquals(res.headers.get("running"), null);
    assertEquals(res.headers.get("link"), null);
    assertEquals(await res.text(), RFC9292_CONTENT);
  });

  it("should decode a known-length response with informational responses", async () => {
    const res = decodeResponse(
      bin(
        1,
        102,
        kfs(["running", '"sleep 15"']),
        103,
        kfs(["link", "</style.css>; rel=preload; as=style"]),
        200,
        kfs(...RFC9292_FINAL_HEADERS),
        lp(RFC9292_CONTENT),
        kfs(),
      ),
    );
    assertEquals(res.status, 200);
    for (const [name, value] of RFC9292_FINAL_HEADERS) {
      assertEquals(res.headers.get(name), value);
    }
    assertEquals(res.headers.get("link"), null);
    assertEquals(await res.text(), RFC9292_CONTENT);
  });

  it("should decode a known-length response with headers and content", async () => {
    // Regression: the field section length must be read before its bounds.
    const res = decodeResponse(
      bin(
        1,
        404,
        kfs(["content-type", "text/plain"], ["x-a", "b"]),
        lp("not found"),
        0,
      ),
    );
    assertEquals(res.status, 404);
    assertEquals(res.headers.get("content-type"), "text/plain");
    assertEquals(res.headers.get("x-a"), "b");
    assertEquals(await res.text(), "not found");
  });

  it("should keep repeated Set-Cookie fields", () => {
    const res = decodeResponse(
      bin(1, 200, kfs(["set-cookie", "a=1"], ["set-cookie", "b=2"])),
    );
    assertEquals(res.headers.getSetCookie(), ["a=1", "b=2"]);
  });

  it("should decode null body statuses", async () => {
    for (const status of [204, 205, 304]) {
      const res = decodeResponse(bin(1, status, kfs(["x-a", "1"]), 0, 0));
      assertEquals(res.status, status);
      assertEquals(res.body, null);
      assertEquals(await res.text(), "");
      assertInvalid(
        () => decodeResponse(bin(1, status, kfs(), lp("x"))),
        "content",
      );
    }
  });

  it("should reject invalid status codes", () => {
    for (const status of [0, 99, 600, 1000]) {
      assertInvalid(
        () => decodeResponse(bin(1, status, kfs())),
        "status code",
      );
    }
  });

  it("should reject a response without a final status", () => {
    assertInvalid(() => decodeResponse(bin(1, 103, kfs())), "truncated");
  });

  it("should reject invalid framing indicators", () => {
    for (const framing of [0, 2, 4]) {
      assertInvalid(
        () => decodeResponse(bin(framing, 200, kfs())),
        "framing indicator",
      );
    }
  });

  it("should reject non-zero padding", () => {
    assertInvalid(
      () => decodeResponse(bin(1, 200, kfs(), 0, 0, new Uint8Array([0, 7]))),
      "padding",
    );
  });
});

describe("encodeRequest", () => {
  it("should encode a GET request in known-length format", async () => {
    const req = new Request("https://www.example.com/hello.txt", {
      headers: { "User-Agent": UA, "Accept-Language": "en, mi" },
    });
    const expected = bin(
      0,
      lp("GET"),
      lp("https"),
      lp("www.example.com"),
      lp("/hello.txt"),
      kfs(["accept-language", "en, mi"], ["user-agent", UA]),
      0,
      0,
    );
    assertEquals(bytesToHex(await encodeRequest(req)), bytesToHex(expected));
  });

  it("should encode port and query, and drop the fragment", async () => {
    const req = new Request("http://example.com:8080/a/b?x=1&y=2#frag");
    const enc = await encodeRequest(req);
    const expected = bin(
      0,
      lp("GET"),
      lp("http"),
      lp("example.com:8080"),
      lp("/a/b?x=1&y=2"),
      kfs(),
      0,
      0,
    );
    assertEquals(bytesToHex(enc), bytesToHex(expected));
    assertEquals(decodeRequest(enc).url, "http://example.com:8080/a/b?x=1&y=2");
  });

  it("should encode Latin-1 field values byte by byte", async () => {
    const req = new Request("https://example.com/", {
      headers: { "x-latin1": "café" },
    });
    const enc = await encodeRequest(req);
    assertEquals(
      bytesToHex(enc).includes(
        bytesToHex(new Uint8Array([4, 0x63, 0x61, 0x66, 0xe9])),
      ),
      true,
    );
    assertEquals(decodeRequest(enc).headers.get("x-latin1"), "café");
  });

  it("should reject an already consumed body", async () => {
    const req = new Request("https://example.com/", {
      method: "POST",
      body: "x",
    });
    await req.text();
    await assertRejects(() => encodeRequest(req), TypeError);
  });
});

describe("encodeResponse", () => {
  it("should encode a response in known-length format", async () => {
    const res = new Response("Hello", {
      status: 201,
      headers: { "Content-Type": "text/plain", "X-A": "b" },
    });
    const expected = bin(
      1,
      201,
      kfs(["content-type", "text/plain"], ["x-a", "b"]),
      lp("Hello"),
      0,
    );
    assertEquals(bytesToHex(await encodeResponse(res)), bytesToHex(expected));
  });

  it("should reject a network error response", async () => {
    await assertRejects(
      () => encodeResponse(Response.error()),
      OhttpError,
      "status",
    );
  });
});

describe("round trip", () => {
  const BODY_SIZES = [0, 1, 63, 64, 16383, 16384, 100000];

  it("should round-trip requests", async () => {
    for (const size of BODY_SIZES) {
      const body = new Uint8Array(size).map((_, i) => i & 0xff);
      const req = new Request("https://example.com/upload?id=1", {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body,
      });
      const decoded = decodeRequest(await encodeRequest(req));
      assertEquals(decoded.method, "POST");
      assertEquals(decoded.url, "https://example.com/upload?id=1");
      assertEquals(
        decoded.headers.get("content-type"),
        "application/octet-stream",
      );
      assertEquals(new Uint8Array(await decoded.arrayBuffer()), body);
    }
  });

  it("should round-trip requests with various methods", async () => {
    for (const method of ["GET", "HEAD", "OPTIONS", "DELETE", "PATCH"]) {
      const req = new Request("https://example.com/", { method });
      const decoded = decodeRequest(await encodeRequest(req));
      assertEquals(decoded.method, method);
    }
  });

  it("should round-trip responses", async () => {
    for (const size of BODY_SIZES) {
      const body = new Uint8Array(size).map((_, i) => (i * 7) & 0xff);
      const res = new Response(body, { status: 200 });
      const decoded = decodeResponse(await encodeResponse(res));
      assertEquals(decoded.status, 200);
      assertEquals(new Uint8Array(await decoded.arrayBuffer()), body);
    }
  });

  it("should round-trip many headers (multi-byte section length)", async () => {
    const headers = new Headers();
    for (let i = 0; i < 100; i++) {
      headers.set(`x-header-${i}`, "v".repeat(i));
    }
    const decoded = decodeResponse(
      await encodeResponse(new Response("ok", { status: 500, headers })),
    );
    assertEquals(decoded.status, 500);
    for (let i = 0; i < 100; i++) {
      assertEquals(decoded.headers.get(`x-header-${i}`), "v".repeat(i));
    }
    assertEquals(await decoded.text(), "ok");
  });

  it("should round-trip repeated Set-Cookie fields", async () => {
    const headers = new Headers();
    headers.append("set-cookie", "a=1");
    headers.append("set-cookie", "b=2");
    const decoded = decodeResponse(
      await encodeResponse(new Response(null, { headers })),
    );
    assertEquals(decoded.headers.getSetCookie(), ["a=1", "b=2"]);
  });

  it("should round-trip a Cookie field", async () => {
    const req = new Request("https://example.com/", {
      headers: { cookie: "a=1; b=2" },
    });
    const decoded = decodeRequest(await encodeRequest(req));
    assertEquals(decoded.headers.get("cookie"), "a=1; b=2");
  });

  it("should round-trip a 204 response", async () => {
    const decoded = decodeResponse(
      await encodeResponse(new Response(null, { status: 204 })),
    );
    assertEquals(decoded.status, 204);
    assertEquals(decoded.body, null);
  });
});
