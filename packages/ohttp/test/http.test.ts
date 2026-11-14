import { assertEquals, assertThrows } from "@std/assert";
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createOhttpClient,
  createOhttpFetchForwarder,
  createOhttpGateway,
  createOhttpHandler,
  createOhttpKeyConfigHandler,
  createStandardEncoding,
  ohttpFetch,
  type OhttpGateway,
} from "../mod.ts";

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
  const handle = createOhttpHandler({
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
