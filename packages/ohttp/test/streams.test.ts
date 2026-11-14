import { assertEquals, assertRejects } from "@std/assert";
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  decodeRequest as decodeKnownRequest,
  decodeResponse as decodeKnownResponse,
} from "../src/bhttp/decoder.ts";
import {
  encodeRequest as encodeKnownRequest,
  encodeResponse as encodeKnownResponse,
} from "../src/bhttp/encoder.ts";
import { createOhttpClient, createOhttpGateway, OhttpError } from "../mod.ts";
import {
  createChunkedEncoding,
  createOhttpGatewayHandler,
  createStandardEncoding,
  ohttpFetch,
} from "../mod.ts";
import {
  decodeRequest,
  decodeResponse,
  encodeRequest,
  encodeResponse,
} from "../src/bhttp.ts";
import {
  collect,
  concat,
  encodeInteger,
  fragments,
  stream,
} from "../src/streams.ts";

async function pair(
  encoding = createChunkedEncoding(),
  streamingUpload = false,
) {
  const kem = new DhkemX25519HkdfSha256();
  const kdf = new HkdfSha256();
  const aead = new Aes128Gcm();
  const keys = await kem.generateKeyPair();
  const gateway = createOhttpGateway({
    kem,
    ...keys,
    keyId: 1,
    encoding,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const client = createOhttpClient({
    kem,
    kdf,
    aead,
    encoding,
    keyConfig: await gateway.publicKeyConfig,
    relayUrl: "https://relay.example/",
    streamingUpload,
  });
  return { client, gateway };
}

Deno.test("HTTP response is available and readable before its source completes", async () => {
  const { client, gateway } = await pair();
  let finish!: () => void;
  const finished = new Promise<void>((resolve) => {
    finish = resolve;
  });
  let completed = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input, init) =>
    createOhttpGatewayHandler({
      gateway,
      forward: () =>
        Promise.resolve(
          new Response(stream((async function* () {
            yield new TextEncoder().encode("early data");
            await finished;
            completed = true;
            yield new TextEncoder().encode("late data");
          })())),
        ),
    })(new Request(input, init));
  try {
    const response = await ohttpFetch(client, "https://target.example/");
    assertEquals(completed, false);
    const reader = response.body!.getReader();
    assertEquals(
      new TextDecoder().decode((await reader.read()).value),
      "early data",
    );
    assertEquals(completed, false);
    finish();
    assertEquals(
      new TextDecoder().decode((await reader.read()).value),
      "late data",
    );
    assertEquals((await reader.read()).done, true);
    reader.releaseLock();
  } finally {
    finish();
    globalThis.fetch = originalFetch;
  }
});

Deno.test("cancel before first body read releases gateway transport and request source", async () => {
  const { client, gateway } = await pair();
  let sourceCancelled = false;
  const source = new ReadableStream<Uint8Array>({
    cancel() {
      sourceCancelled = true;
    },
  });
  const unopened = await client.encapsulateRequest(source);
  await unopened.body.cancel();
  assertEquals(sourceCancelled, true);

  const exchange = await client.encapsulateRequest([new Uint8Array([1])]);
  const wire = await collect(exchange.body);
  let cancelled = false;
  const transport = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(wire);
    },
    cancel() {
      cancelled = true;
    },
  });
  const received = await gateway.decapsulateRequest(transport);
  await received.body.cancel();
  assertEquals(cancelled, true);
  assertEquals(transport.locked, false);
});

Deno.test("chunked response rejects truncation, modified final tag and reordered chunks", async () => {
  for (const mode of ["truncate", "modify", "reorder"]) {
    const { client, gateway } = await pair();
    const sent = await client.encapsulateRequest([]);
    const received = await gateway.decapsulateRequest(sent.body);
    await collect(received.body);
    const response = await received.encapsulateResponse([
      new Uint8Array([1]),
      new Uint8Array([2]),
    ]);
    let wire = await collect(response.body);
    if (mode === "truncate") wire = wire.slice(0, -17);
    if (mode === "modify") wire[wire.length - 1] ^= 1;
    if (mode === "reorder") {
      const first = wire.slice(16, 34);
      wire.copyWithin(16, 34, 52);
      wire.set(first, 34);
    }
    await assertRejects(async () =>
      collect(await sent.decapsulateResponse([wire]))
    );
  }
});

Deno.test("binary HTTP streaming adapter interoperates with known-length codec", async () => {
  const request = new Request("https://example.com/path?q=1", {
    method: "POST",
    body: "payload",
    headers: { "x-test": "value" },
  });
  const encoded = await collect(encodeRequest(request));
  assertEquals(
    await decodeKnownRequest(encoded).text(),
    "payload",
  );
  const knownRequest = await encodeKnownRequest(
    new Request("https://example.com/", { method: "POST", body: "known" }),
  );
  const decoded = await decodeRequest(
    stream(fragments(Array.from(knownRequest, (b) => new Uint8Array([b])))),
  );
  assertEquals(await decoded.text(), "known");
  const knownResponse = await encodeKnownResponse(
    new Response("known response", { status: 201 }),
  );
  assertEquals(
    await (await decodeResponse(stream(fragments([knownResponse])))).text(),
    "known response",
  );
  const response = decodeKnownResponse(
    await collect(encodeResponse(new Response("stream response"))),
  );
  assertEquals(await response.text(), "stream response");
});

Deno.test("binary HTTP EOF validates padding, content and null-body status", async () => {
  for (
    const bytes of [
      new Uint8Array([3, 0x40, 200, 0, 2, 65]), // truncated content chunk
      new Uint8Array([3, 0x40, 200, 0, 0, 0, 1]), // nonzero padding
      new Uint8Array([3, 0x40, 200, 0, 0, 1]), // truncated trailer name
    ]
  ) {
    const response = await decodeResponse(stream(fragments([bytes])));
    await assertRejects(() => response.text());
  }
  const empty = await decodeResponse(
    stream(fragments([new Uint8Array([3, 0x40, 204, 0, 0, 0])])),
  );
  assertEquals(empty.status, 204);
  assertEquals(empty.body, null);
  // RFC 9292 allows omitted empty sections.
  const omitted = await decodeResponse(
    stream(fragments([new Uint8Array([1, 0x40, 200])])),
  );
  assertEquals(await omitted.text(), "");
  // Informational status and headers precede the final response.
  const informational = await decodeResponse(
    stream(fragments([new Uint8Array([3, 0x40, 103, 0, 0x40, 200, 0, 0, 0])])),
  );
  assertEquals(informational.status, 200);
  assertEquals(await informational.text(), "");
});

Deno.test("AbortSignal cancels a blocked upload during standard encoding", async () => {
  const { createStandardEncoding } = await import("../mod.ts");
  const { client: chunked, gateway } = await pair();
  const kem = new DhkemX25519HkdfSha256();
  const client = createOhttpClient({
    kem,
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
    encoding: createStandardEncoding(),
    keyConfig: await gateway.publicKeyConfig,
    relayUrl: chunked.relayUrl,
  });
  let cancelled = false;
  const upload = new ReadableStream<Uint8Array>({
    cancel() {
      cancelled = true;
    },
  });
  const controller = new AbortController();
  const operation = ohttpFetch(client, "https://target.example/upload", {
    method: "POST",
    body: upload,
    signal: controller.signal,
    duplex: "half",
  } as RequestInit);
  controller.abort();
  await assertRejects(() => operation);
  assertEquals(cancelled, true);
});

Deno.test("HTTP body cancellation propagates to the encrypted transport", async () => {
  const { client, gateway } = await pair();
  let cancelled = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const response = await createOhttpGatewayHandler({
      gateway,
      forward: () =>
        Promise.resolve(
          new Response(
            new ReadableStream<Uint8Array>({
              start(controller) {
                controller.enqueue(new Uint8Array([65]));
              },
              cancel() {
                cancelled = true;
              },
            }),
          ),
        ),
    })(new Request(input, init));
    return response;
  };
  try {
    const response = await ohttpFetch(client, "https://target.example/");
    await response.body!.cancel();
    assertEquals(cancelled, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

async function deadline<T>(promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("Cancellation did not settle")),
          1000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

Deno.test("HTTP cancellation interrupts a pending upstream body read", async () => {
  for (const abortRead of [false, true]) {
    const { client, gateway } = await pair();
    let waiting!: () => void;
    const pending = new Promise<void>((resolve) => {
      waiting = resolve;
    });
    let cancelled = false;
    let pulls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (input, init) =>
      createOhttpGatewayHandler({
        gateway,
        forward: () =>
          Promise.resolve(
            new Response(
              new ReadableStream<Uint8Array>({
                pull(controller) {
                  if (pulls++ === 0) {
                    controller.enqueue(new Uint8Array([65]));
                    return;
                  }
                  waiting();
                  return new Promise<void>(() => {});
                },
                cancel() {
                  cancelled = true;
                },
              }, { highWaterMark: 0 }),
            ),
          ),
      })(new Request(input, init));
    const abort = new AbortController();
    try {
      const response = await ohttpFetch(client, "https://target.example/", {
        signal: abort.signal,
      });
      const reader = response.body!.getReader();
      assertEquals((await reader.read()).value, new Uint8Array([65]));
      const next = reader.read();
      // Wait until the upstream is actually blocked, rather than using a sleep.
      await pending;
      if (abortRead) {
        const rejected = assertRejects(() => next);
        abort.abort();
        await deadline(rejected);
      } else {
        await deadline(reader.cancel());
        assertEquals((await next).done, true);
      }
      assertEquals(cancelled, true);
      reader.releaseLock();
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
});

Deno.test("gateway cancellation interrupts a pending encrypted request read", async () => {
  const { client, gateway } = await pair();
  const exchange = await client.encapsulateRequest([new Uint8Array([7])]);
  const bytes = await collect(exchange.body);
  let waiting!: () => void;
  const pending = new Promise<void>((resolve) => {
    waiting = resolve;
  });
  let cancelled = false;
  let sent = false;
  const transport = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (!sent) {
        sent = true;
        controller.enqueue(bytes.slice(0, -17));
        return;
      }
      waiting();
      return new Promise<void>(() => {});
    },
    cancel() {
      cancelled = true;
    },
  }, { highWaterMark: 0 });
  const received = await gateway.decapsulateRequest(transport);
  const reader = received.body.getReader();
  assertEquals((await reader.read()).value, new Uint8Array([7]));
  const next = reader.read();
  await pending;
  await deadline(reader.cancel());
  assertEquals((await next).done, true);
  assertEquals(cancelled, true);
  assertEquals(transport.locked, false);
  reader.releaseLock();
});

function binaryRequest(
  method = "GET",
  value?: string,
  authority = "example.com",
  path = "/",
): Uint8Array {
  const text = (s: string) => {
    const bytes = new TextEncoder().encode(s);
    return concat([encodeInteger(bytes.length), bytes]);
  };
  return concat([
    new Uint8Array([2]),
    text(method),
    text("https"),
    text(authority),
    text(path),
    ...(value === undefined ? [] : [text("x-test"), text(value)]),
    new Uint8Array([0, 0, 0]),
  ]);
}

for (const encoding of [createStandardEncoding(), createChunkedEncoding()]) {
  Deno.test(
    encoding.requestContentType +
      ": invalid input is 400, forward failures propagate",
    async () => {
      const { client, gateway } = await pair(encoding);
      let forwarded = 0;
      const handler = createOhttpGatewayHandler({
        gateway,
        forward() {
          forwarded++;
          throw new TypeError("upstream network failure");
        },
      });
      for (
        const bytes of [
          binaryRequest("TRACE"),
          binaryRequest("GET", "bad\r\nvalue"),
          new Uint8Array([99]),
        ]
      ) {
        const ctx = await client.encapsulateRequest([bytes]);
        const response = await handler(
          new Request("https://gateway.example/", {
            method: "POST",
            headers: { "Content-Type": encoding.requestContentType },
            body: (await collect(ctx.body)).buffer as ArrayBuffer,
          }),
        );
        assertEquals(response.status, 400);
      }
      assertEquals(forwarded, 0);
      const valid = await client.encapsulateRequest([binaryRequest()]);
      const wire = await collect(valid.body);
      for (
        const bad of [
          new Uint8Array(40),
          wire.slice(0, 5),
          wire.slice(0, -1),
          wire.slice(),
        ]
      ) {
        if (bad.length === wire.length) bad[bad.length - 1] ^= 1;
        assertEquals(
          (await handler(
            new Request("https://gateway.example/", {
              method: "POST",
              headers: { "Content-Type": encoding.requestContentType },
              body: bad.buffer as ArrayBuffer,
            }),
          )).status,
          400,
        );
      }
      const fresh = await client.encapsulateRequest([binaryRequest()]);
      await assertRejects(
        () =>
          handler(
            new Request("https://gateway.example/", {
              method: "POST",
              headers: { "Content-Type": encoding.requestContentType },
              body: fresh.body,
              duplex: "half",
            } as RequestInit),
          ),
        TypeError,
        "upstream network failure",
      );
      assertEquals(forwarded, 1);
    },
  );

  Deno.test(
    encoding.requestContentType +
      ": strips hop-by-hop headers, cleans up encoding errors",
    async () => {
      const { client, gateway } = await pair(encoding);
      const originalFetch = globalThis.fetch;
      let cancelled = false;
      let tooLarge = false;
      globalThis.fetch = (input, init) =>
        createOhttpGatewayHandler({
          gateway,
          forward: () =>
            Promise.resolve(
              new Response(
                new ReadableStream<Uint8Array>({
                  start(controller) {
                    if (!tooLarge) {
                      controller.enqueue(new Uint8Array([65]));
                      controller.close();
                    }
                  },
                  cancel() {
                    cancelled = true;
                  },
                }),
                {
                  headers: tooLarge ? { "x-large": "x".repeat(65536) } : {
                    "connection": "keep-alive, X-Private",
                    "transfer-encoding": "chunked",
                    "keep-alive": "timeout=5",
                    "x-private": "remove",
                    "x-end-to-end": "keep",
                  },
                },
              ),
            ),
        })(new Request(input, init));
      try {
        const response = await ohttpFetch(client, "https://target.example/");
        assertEquals(await response.text(), "A");
        for (
          const name of [
            "connection",
            "transfer-encoding",
            "keep-alive",
            "x-private",
          ]
        ) assertEquals(response.headers.has(name), false);
        assertEquals(response.headers.get("x-end-to-end"), "keep");
        tooLarge = true;
        await assertRejects(() =>
          ohttpFetch(client, "https://target.example/")
        );
        assertEquals(cancelled, true);
      } finally {
        globalThis.fetch = originalFetch;
      }
    },
  );
}

Deno.test("bodyless chunked fetch uses buffered upload without duplex", async () => {
  const { client, gateway } = await pair();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    assertEquals(init?.body instanceof ArrayBuffer, true);
    assertEquals((init as RequestInit & { duplex?: string }).duplex, undefined);
    return createOhttpGatewayHandler({
      gateway,
      forward: () => Promise.resolve(new Response("ok")),
    })(new Request(input, init));
  };
  try {
    assertEquals(
      await (await ohttpFetch(client, "https://target.example/")).text(),
      "ok",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("relay streaming upload is explicit and is unnecessary for bodyless GET", async () => {
  for (const enabled of [false, true]) {
    const { client, gateway } = await pair(createChunkedEncoding(), enabled);
    const originalFetch = globalThis.fetch;
    let post = true;
    globalThis.fetch = (input, init) => {
      const streaming = enabled && post;
      assertEquals(init?.body instanceof ReadableStream, streaming);
      assertEquals(
        (init as RequestInit & { duplex?: string }).duplex,
        streaming ? "half" : undefined,
      );
      return createOhttpGatewayHandler({
        gateway,
        async forward(request) {
          if (post) assertEquals(await request.text(), "upload");
          return new Response("ok");
        },
      })(new Request(input, init));
    };
    try {
      const response = await ohttpFetch(client, "https://target.example/", {
        method: "POST",
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode("upload"));
            controller.close();
          },
        }),
        duplex: "half",
      } as RequestInit);
      assertEquals(await response.text(), "ok");
      post = false;
      assertEquals(
        await (await ohttpFetch(client, "https://target.example/")).text(),
        "ok",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
});

Deno.test("late binary HTTP request errors consumed by forward produce 400", async () => {
  const { client, gateway } = await pair();
  const malformed = concat([
    binaryRequest("POST").slice(0, -2),
    new Uint8Array([3, 65]),
  ]);
  const exchange = await client.encapsulateRequest([malformed]);
  const response = await createOhttpGatewayHandler({
    gateway,
    async forward(request) {
      await request.text();
      return new Response("unexpected");
    },
  })(
    new Request("https://gateway.example/", {
      method: "POST",
      body: exchange.body,
      duplex: "half",
      headers: { "Content-Type": client.encoding.requestContentType },
    } as RequestInit),
  );
  assertEquals(response.status, 400);
});

Deno.test("abort interrupts a pending response nonce read in both encodings", async () => {
  for (const encoding of [createStandardEncoding(), createChunkedEncoding()]) {
    const { client } = await pair(encoding);
    let waiting!: () => void;
    const pending = new Promise<void>((resolve) => {
      waiting = resolve;
    });
    let cancelled = false;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = () =>
      Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            pull() {
              waiting();
              return new Promise<void>(() => {});
            },
            cancel() {
              cancelled = true;
            },
          }, { highWaterMark: 0 }),
          { headers: { "Content-Type": encoding.responseContentType } },
        ),
      );
    const abort = new AbortController();
    try {
      const operation = ohttpFetch(client, "https://target.example/", {
        signal: abort.signal,
      });
      const rejected = assertRejects(() => operation);
      await pending;
      abort.abort();
      await deadline(rejected);
      assertEquals(cancelled, true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
});

Deno.test("unexpected TypeErrors in decapsulation or decoded input are not hidden as 400", async () => {
  for (const failInBody of [false, true]) {
    const base = createChunkedEncoding();
    const bug = new TypeError("unexpected implementation failure");
    const { client, gateway } = await pair({
      ...base,
      async decapsulateRequest(...args) {
        if (!failInBody) throw bug;
        const ctx = await base.decapsulateRequest(...args);
        await ctx.body.cancel();
        return {
          ...ctx,
          body: new ReadableStream<Uint8Array>({
            start(controller) {
              controller.error(bug);
            },
          }),
        };
      },
    });
    const exchange = await client.encapsulateRequest([binaryRequest()]);
    const handler = createOhttpGatewayHandler({
      gateway,
      forward() {
        throw new Error("must not forward malformed input");
      },
    });
    const error = await assertRejects(
      () =>
        handler(
          new Request("https://gateway.example/", {
            method: "POST",
            body: exchange.body,
            duplex: "half",
            headers: { "Content-Type": base.requestContentType },
          } as RequestInit),
        ),
      TypeError,
      "unexpected implementation failure",
    );
    assertEquals(error, bug);
  }
});

Deno.test("invalid authority/path cannot change the binary HTTP target", async () => {
  const { client, gateway } = await pair();
  let forwarded = 0;
  const handle = createOhttpGatewayHandler({
    gateway,
    forward() {
      forwarded++;
      return Promise.resolve(new Response("ok"));
    },
  });
  for (
    const [authority, path] of [
      ["target.example", "@evil.example/x"],
      ["target.example", "x"],
      ["target.example@evil.example", "/"],
      ["target.example/evil", "/"],
      ["target.example?query", "/"],
      ["target.example#fragment", "/"],
      ["target.example", "/x#fragment"],
      ["target.example", "/x\\evil"],
    ]
  ) {
    const exchange = await client.encapsulateRequest([
      binaryRequest("GET", undefined, authority, path),
    ]);
    const response = await handle(
      new Request("https://gateway.example/", {
        method: "POST",
        headers: { "Content-Type": client.encoding.requestContentType },
        body: exchange.body,
        duplex: "half",
      } as RequestInit),
    );
    assertEquals(response.status, 400);
  }
  assertEquals(forwarded, 0);
});

Deno.test("response authentication errors are OhttpError with their original cause", async () => {
  for (const encoding of [createStandardEncoding(), createChunkedEncoding()]) {
    const { client, gateway } = await pair(encoding);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const response = await createOhttpGatewayHandler({
        gateway,
        forward: () => Promise.resolve(new Response("response")),
      })(new Request(input, init));
      const bytes = new Uint8Array(await response.arrayBuffer());
      bytes[bytes.length - 1] ^= 1;
      return new Response(bytes, { headers: response.headers });
    };
    try {
      const error = await assertRejects(
        async () => {
          const response = await ohttpFetch(client, "https://target.example/");
          await response.text();
        },
        OhttpError,
        "Response decryption failed",
      );
      assertEquals(error.cause instanceof DOMException, true);
      assertEquals((error.cause as DOMException).name, "OperationError");
    } finally {
      globalThis.fetch = originalFetch;
    }
  }
});

Deno.test("binary HTTP length and data share one encrypted chunk", async () => {
  const { client, gateway } = await pair();
  const request = new Request("https://target.example/", {
    method: "POST",
    duplex: "half",
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < 4; i++) {
          controller.enqueue(new Uint8Array(10).fill(65));
        }
        controller.close();
      },
    }),
  } as RequestInit);
  const exchange = await client.encapsulateRequest(encodeRequest(request));
  const pieces: Uint8Array[] = [];
  for await (const piece of fragments(exchange.body)) pieces.push(piece);
  // Wire header, binary HTTP control, four content chunks, terminators, final.
  assertEquals(pieces.length, 8);
  const received = await gateway.decapsulateRequest(pieces);
  assertEquals(
    await (await decodeRequest(received.body)).text(),
    "A".repeat(40),
  );
});
