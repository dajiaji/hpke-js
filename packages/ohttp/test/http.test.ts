import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createChunkedEncoding,
  createOhttpClient,
  createOhttpFetchForwarder,
  createOhttpGateway,
  createOhttpGatewayHandler,
  createOhttpKeyConfigHandler,
  createOhttpRelayHandler,
  createStandardEncoding,
  ohttpFetch,
  type OhttpGateway,
} from "../mod.ts";

function fieldNames(headers: Headers): string[] {
  const names: string[] = [];
  headers.forEach((_, name) => names.push(name));
  return names.sort();
}

async function createGateway(): Promise<OhttpGateway> {
  const kem = new DhkemX25519HkdfSha256();
  return createOhttpGateway({
    keyId: 1,
    kem,
    ...(await kem.generateKeyPair()),
    kdfAeadPairs: [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }],
    encoding: createStandardEncoding(),
  });
}

Deno.test("key config handler serves application/ohttp-keys", async () => {
  const gateway = await createGateway();
  const keyConfig = await gateway.publicKeyConfig;
  const handle = createOhttpKeyConfigHandler(gateway);

  const response = await handle(new Request("https://gateway.example/keys"));
  assertEquals(response.status, 200);
  assertEquals(response.headers.get("content-type"), "application/ohttp-keys");
  assertEquals(
    response.headers.get("content-length"),
    String(keyConfig.length),
  );
  assertEquals(new Uint8Array(await response.arrayBuffer()), keyConfig);

  const head = await handle(
    new Request("https://gateway.example/keys", { method: "HEAD" }),
  );
  assertEquals(head.status, 200);
  assertEquals(head.headers.get("content-type"), "application/ohttp-keys");
  assertEquals(head.headers.get("content-length"), String(keyConfig.length));
  assertEquals(head.body, null);
});

Deno.test("key config handler rejects other methods", async () => {
  const handle = createOhttpKeyConfigHandler(await createGateway());
  const response = await handle(
    new Request("https://gateway.example/keys", { method: "POST", body: "x" }),
  );
  assertEquals(response.status, 405);
  assertEquals(response.headers.get("allow"), "GET, HEAD");
});

Deno.test("fetch forwarder fetches allowed origins without following redirects", async () => {
  const calls: { request: Request; init?: RequestInit }[] = [];
  const forward = createOhttpFetchForwarder({
    allowedOrigins: [
      "https://target.example/ignored/path",
      new URL("http://localhost:8080"),
    ],
    fetch(request, init) {
      calls.push({ request, init });
      return Promise.resolve(
        new Response("decoded body", {
          status: 201,
          statusText: "Created",
          headers: {
            "content-encoding": "gzip",
            "content-length": "5",
            "x-upstream": "preserved",
          },
        }),
      );
    },
  });

  const request = new Request("https://target.example/api?q=1");
  const response = await forward(request);
  assertEquals(calls.length, 1);
  assertEquals(calls[0].request, request);
  assertEquals(calls[0].init?.redirect, "manual");
  assertEquals(response.status, 201);
  assertEquals(response.statusText, "Created");
  assertEquals(response.headers.get("content-encoding"), null);
  assertEquals(response.headers.get("content-length"), null);
  assertEquals(response.headers.get("x-upstream"), "preserved");
  assertEquals(await response.text(), "decoded body");

  await forward(new Request("http://localhost:8080/"));
  assertEquals(calls.length, 2);
});

Deno.test("fetch forwarder keeps the headers of bodiless responses", async () => {
  const upstream = new Response(null, {
    status: 302,
    headers: { location: "https://elsewhere.example/", "content-length": "0" },
  });
  const forward = createOhttpFetchForwarder({
    allowedOrigins: ["https://target.example"],
    fetch: () => Promise.resolve(upstream),
  });
  const response = await forward(new Request("https://target.example/"));
  assertEquals(response, upstream);
  assertEquals(response.headers.get("content-length"), "0");
});

Deno.test("fetch forwarder answers 403 for other origins", async () => {
  let called = false;
  const forward = createOhttpFetchForwarder({
    allowedOrigins: ["https://target.example"],
    fetch() {
      called = true;
      return Promise.resolve(new Response("unreachable"));
    },
  });
  for (
    const url of [
      "http://target.example/",
      "https://target.example:8443/",
      "https://sub.target.example/",
      "https://target.example.attacker.example/",
    ]
  ) {
    const request = new Request(url, { method: "POST", body: "payload" });
    const response = await forward(request);
    assertEquals(response.status, 403);
    assertEquals(response.body, null);
  }
  assertEquals(called, false);
});

Deno.test("fetch forwarder rejects invalid allowed origins", () => {
  assertThrows(
    () => createOhttpFetchForwarder({ allowedOrigins: ["not a url"] }),
    TypeError,
  );
  assertThrows(
    () => createOhttpFetchForwarder({ allowedOrigins: ["data:text/plain,x"] }),
    Error,
    "Invalid allowed origin",
  );
});

Deno.test("fetch forwarder works behind the OHTTP handler", async () => {
  const gateway = await createGateway();
  const handle = createOhttpGatewayHandler({
    gateway,
    forward: createOhttpFetchForwarder({
      allowedOrigins: ["https://target.example"],
      fetch: async (request) =>
        new Response(`${request.method} ${await request.text()}`, {
          headers: { "content-length": "999" },
        }),
    }),
  });
  const client = createOhttpClient({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
    encoding: createStandardEncoding(),
    keyConfig: await gateway.publicKeyConfig,
    relayUrl: "https://relay.example/ohttp",
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (input, init) => handle(new Request(input, init));
  try {
    const allowed = await ohttpFetch(client, "https://target.example/api", {
      method: "POST",
      body: "hello",
    });
    assertEquals(allowed.status, 200);
    assertEquals(await allowed.text(), "POST hello");

    const denied = await ohttpFetch(client, "https://other.example/api", {
      method: "POST",
      body: "hello",
    });
    assertEquals(denied.status, 403);
    assertEquals(await denied.text(), "");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("relay handler forwards only the OHTTP fields to the gateway", async () => {
  const calls: Request[] = [];
  const bodies: Uint8Array[] = [];
  const relay = createOhttpRelayHandler({
    gatewayUrl: "https://gateway.example/gateway",
    async fetch(request) {
      calls.push(request);
      bodies.push(new Uint8Array(await request.arrayBuffer()));
      return new Response(new Uint8Array([4, 5, 6]), {
        status: 200,
        headers: {
          "content-type": "message/ohttp-res",
          "incremental": "?1",
          "set-cookie": "gateway=1",
          "x-gateway": "internal",
        },
      });
    },
  });
  const response = await relay(
    new Request("https://relay.example/ohttp?client=1", {
      method: "POST",
      headers: {
        "content-type": "Message/OHTTP-Req; charset=binary",
        "incremental": "?1",
        "authorization": "Bearer secret",
        "cookie": "session=1",
        "forwarded": "for=192.0.2.1",
        "x-forwarded-for": "192.0.2.1",
        "user-agent": "client",
      },
      body: new Uint8Array([1, 2, 3]),
    }),
  );
  assertEquals(calls.length, 1);
  assertEquals(calls[0].url, "https://gateway.example/gateway");
  assertEquals(calls[0].method, "POST");
  assertEquals(calls[0].redirect, "error");
  assertEquals(
    fieldNames(calls[0].headers),
    ["content-type", "incremental"],
  );
  assertEquals(
    calls[0].headers.get("content-type"),
    "Message/OHTTP-Req; charset=binary",
  );
  assertEquals(bodies[0], new Uint8Array([1, 2, 3]));

  assertEquals(response.status, 200);
  assertEquals(
    fieldNames(response.headers),
    ["content-type", "incremental"],
  );
  assertEquals(response.headers.get("content-type"), "message/ohttp-res");
  assertEquals(
    new Uint8Array(await response.arrayBuffer()),
    new Uint8Array([4, 5, 6]),
  );
});

Deno.test("relay handler returns the gateway's error status", async () => {
  const relay = createOhttpRelayHandler({
    gatewayUrl: new URL("https://gateway.example/gateway"),
    fetch: () => Promise.resolve(new Response(null, { status: 400 })),
  });
  const response = await relay(
    new Request("https://relay.example/ohttp", {
      method: "POST",
      headers: { "content-type": "message/ohttp-chunked-req" },
      body: new Uint8Array([1]),
    }),
  );
  assertEquals(response.status, 400);
  assertEquals(fieldNames(response.headers), []);
});

Deno.test("relay handler rejects requests that are not OHTTP requests", async () => {
  let called = false;
  const relay = createOhttpRelayHandler({
    gatewayUrl: "https://gateway.example/gateway",
    fetch() {
      called = true;
      return Promise.resolve(new Response(null));
    },
  });
  const get = await relay(new Request("https://relay.example/ohttp"));
  assertEquals(get.status, 405);
  assertEquals(get.headers.get("allow"), "POST");
  for (
    const init of [
      { headers: { "content-type": "application/json" }, body: "{}" },
      { headers: { "content-type": "message/ohttp-res" }, body: "x" },
      { body: new Uint8Array([1]) },
      { headers: { "content-type": "message/ohttp-req" } },
    ]
  ) {
    const response = await relay(
      new Request("https://relay.example/ohttp", { method: "POST", ...init }),
    );
    assertEquals(response.status, 415);
  }
  assertEquals(called, false);
});

Deno.test("handlers cancel the body of a request with a disallowed method", async () => {
  const gateway = await createGateway();
  const handlers: [string, (request: Request) => Promise<Response>][] = [
    [
      "PUT",
      createOhttpGatewayHandler({
        gateway,
        forward: () => Promise.resolve(new Response(null)),
      }),
    ],
    ["POST", createOhttpKeyConfigHandler(gateway)],
    [
      "PUT",
      createOhttpRelayHandler({
        gatewayUrl: "https://gateway.example/gateway",
        fetch: () => Promise.resolve(new Response(null)),
      }),
    ],
  ];
  for (const [method, handle] of handlers) {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      },
    });
    const response = await handle(
      new Request("https://example.com/", {
        method,
        headers: { "content-type": "message/ohttp-req" },
        body,
        duplex: "half",
      } as RequestInit),
    );
    assertEquals(response.status, 405);
    await new Promise((resolve) => setTimeout(resolve, 0));
    assertEquals(cancelled, true);
  }
});

Deno.test("relay handler buffers uploads unless streaming is enabled", async () => {
  for (const streamingUpload of [false, true]) {
    let pulled = 0;
    let pulledBeforeFetch = -1;
    const relay = createOhttpRelayHandler({
      gatewayUrl: "https://gateway.example/gateway",
      streamingUpload,
      async fetch(request) {
        pulledBeforeFetch = pulled;
        return new Response(await request.arrayBuffer());
      },
    });
    const response = await relay(
      new Request(
        "https://relay.example/ohttp",
        {
          method: "POST",
          headers: { "content-type": "message/ohttp-chunked-req" },
          body: new ReadableStream<Uint8Array>({
            pull(controller) {
              if (++pulled > 3) controller.close();
              else controller.enqueue(new Uint8Array([pulled]));
            },
          }, { highWaterMark: 0 }),
          duplex: "half",
        } as RequestInit,
      ),
    );
    assertEquals(
      new Uint8Array(await response.arrayBuffer()),
      new Uint8Array([1, 2, 3]),
    );
    assertEquals(pulledBeforeFetch === 4, !streamingUpload);
  }
});

Deno.test("relay handler validates the gateway URL and propagates failures", async () => {
  assertThrows(
    () => createOhttpRelayHandler({ gatewayUrl: "not a url" }),
    TypeError,
  );
  const failure = new TypeError("unreachable");
  const relay = createOhttpRelayHandler({
    gatewayUrl: "https://gateway.example/gateway",
    fetch: () => Promise.reject(failure),
  });
  const error = await assertRejects(() =>
    relay(
      new Request("https://relay.example/ohttp", {
        method: "POST",
        headers: { "content-type": "message/ohttp-req" },
        body: new Uint8Array([1]),
      }),
    )
  );
  assertEquals(error, failure);
});

for (const createEncoding of [createStandardEncoding, createChunkedEncoding]) {
  const encoding = createEncoding();
  Deno.test(
    `relay handler connects a client to a gateway: ${encoding.requestContentType}`,
    async () => {
      const kem = new DhkemX25519HkdfSha256();
      const kdf = new HkdfSha256();
      const aead = new Aes128Gcm();
      const gateway = createOhttpGateway({
        keyId: 1,
        kem,
        ...(await kem.generateKeyPair()),
        kdfAeadPairs: [{ kdf, aead }],
        encoding,
      });
      const gatewayHandler = createOhttpGatewayHandler({
        gateway,
        forward: async (request) =>
          new Response(`${request.method} ${await request.text()}`, {
            status: 201,
          }),
      });
      const relay = createOhttpRelayHandler({
        gatewayUrl: "https://gateway.example/gateway",
        streamingUpload: encoding.incremental,
        fetch: (request) => gatewayHandler(request),
      });
      const client = createOhttpClient({
        kem,
        kdf,
        aead,
        encoding,
        keyConfig: await gateway.publicKeyConfig,
        relayUrl: "https://relay.example/ohttp",
      });
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (input, init) => relay(new Request(input, init));
      try {
        const response = await ohttpFetch(client, "https://target.example/", {
          method: "POST",
          body: "hello",
        });
        assertEquals(response.status, 201);
        assertEquals(await response.text(), "POST hello");
      } finally {
        globalThis.fetch = originalFetch;
      }
    },
  );
}
