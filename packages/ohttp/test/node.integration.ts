// Listens on local ports, so it runs with the integration tests:
// deno test --allow-net packages/ohttp/test/node.integration.ts
import { assert, assertEquals } from "@std/assert";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { connect } from "node:net";
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createChunkedEncoding,
  createOhttpClient,
  createOhttpGateway,
  createOhttpGatewayHandler,
  createOhttpKeyConfigHandler,
  createStandardEncoding,
  ohttpFetch,
} from "../mod.ts";
import { type NodeListenerOptions, toNodeListener } from "../node.ts";

type FetchHandler = (request: Request) => Response | Promise<Response>;

async function serve(
  handler: FetchHandler,
  options?: NodeListenerOptions,
): Promise<{ origin: string; close(): Promise<void> }> {
  const server: Server = createServer(toNodeListener(handler, options));
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve())
  );
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
        server.closeAllConnections();
      }),
  };
}

for (const encoding of [createStandardEncoding(), createChunkedEncoding()]) {
  Deno.test(
    `node listener serves an OHTTP gateway: ${encoding.requestContentType}`,
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
      const ohttp = createOhttpGatewayHandler({
        gateway,
        forward: async (request) =>
          new Response(
            `${request.method} ${new URL(request.url).pathname} ${await request
              .text()}`,
            { status: 201, headers: { "x-target": "ok" } },
          ),
      });
      const keys = createOhttpKeyConfigHandler(gateway);
      const server = await serve((request) => {
        const { pathname } = new URL(request.url);
        if (pathname === "/ohttp-keys") return keys(request);
        if (pathname === "/gateway") return ohttp(request);
        return new Response(null, { status: 404 });
      });
      try {
        const keyConfigResponse = await fetch(`${server.origin}/ohttp-keys`);
        assertEquals(
          keyConfigResponse.headers.get("content-type"),
          "application/ohttp-keys",
        );
        const keyConfig = new Uint8Array(await keyConfigResponse.arrayBuffer());
        assertEquals(keyConfig, await gateway.publicKeyConfig);

        const client = createOhttpClient({
          kem,
          kdf,
          aead,
          encoding,
          keyConfig,
          relayUrl: `${server.origin}/gateway`,
        });
        const payload = "payload".repeat(10000);
        const response = await ohttpFetch(client, "https://target.example/a", {
          method: "POST",
          body: payload,
        });
        assertEquals(response.status, 201);
        assertEquals(response.headers.get("x-target"), "ok");
        assertEquals(await response.text(), `POST /a ${payload}`);

        const missing = await fetch(`${server.origin}/missing`);
        assertEquals(missing.status, 404);
        assertEquals(await missing.text(), "");
      } finally {
        await server.close();
      }
    },
  );
}

Deno.test("node listener converts requests and responses", async () => {
  let received: Request | undefined;
  let body = "";
  const server = await serve(async (request) => {
    received = request;
    body = await request.text();
    const headers = new Headers({ "x-reply": "a" });
    headers.append("x-reply", "b");
    headers.append("set-cookie", "a=1");
    headers.append("set-cookie", "b=2");
    return new Response("created", {
      status: 201,
      statusText: "Made",
      headers,
    });
  });
  try {
    const response = await fetch(`${server.origin}/path?q=1`, {
      method: "PUT",
      headers: { "x-test": "request" },
      body: "hello",
    });
    assertEquals(received?.method, "PUT");
    assertEquals(received?.url, `${server.origin}/path?q=1`);
    assertEquals(received?.headers.get("x-test"), "request");
    assertEquals(body, "hello");
    assertEquals(response.status, 201);
    assertEquals(response.headers.get("x-reply"), "a, b");
    assertEquals(response.headers.getSetCookie(), ["a=1", "b=2"]);
    assertEquals(await response.text(), "created");

    const head = await fetch(`${server.origin}/`, { method: "HEAD" });
    assertEquals(received?.method, "HEAD");
    assertEquals(received?.body, null);
    assertEquals(head.status, 201);
    assertEquals(await head.text(), "");
  } finally {
    await server.close();
  }
});

Deno.test("node listener does not read the body of a HEAD response", async () => {
  let pulled = 0;
  let cancelled = false;
  const server = await serve(() =>
    new Response(
      // This body never ends.
      new ReadableStream<Uint8Array>({
        pull(controller) {
          pulled++;
          controller.enqueue(new Uint8Array(1024));
        },
        cancel() {
          cancelled = true;
          // Cancellation never completes, as with a tee() branch whose
          // sibling is still being read.
          return new Promise<void>(() => {});
        },
      }, { highWaterMark: 0 }),
      { headers: { "x-test": "head" } },
    )
  );
  try {
    const response = await fetch(`${server.origin}/`, {
      method: "HEAD",
      signal: AbortSignal.timeout(5000),
    });
    assertEquals(response.status, 200);
    assertEquals(response.headers.get("x-test"), "head");
    assertEquals(await response.text(), "");
    assertEquals(pulled, 0);
    assertEquals(cancelled, true);
  } finally {
    await server.close();
  }
});

Deno.test("node listener answers 500 when the handler fails", async () => {
  const errors: unknown[] = [];
  const failure = new Error("boom");
  const server = await serve(() => Promise.reject(failure), {
    onError: (error) => errors.push(error),
  });
  try {
    const response = await fetch(`${server.origin}/`);
    assertEquals(response.status, 500);
    assertEquals(await response.text(), "");
    assertEquals(errors, [failure]);
  } finally {
    await server.close();
  }
});

Deno.test("node listener closes the connection when the body fails", async () => {
  const errors: unknown[] = [];
  const failure = new Error("boom");
  const server = await serve(
    () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(controller) {
            controller.error(failure);
          },
        }),
      ),
    { onError: (error) => errors.push(error) },
  );
  try {
    let failed = false;
    try {
      await (await fetch(`${server.origin}/`)).text();
    } catch {
      failed = true;
    }
    assert(failed);
    // A client may retry a request whose connection was reset.
    assert(errors.length > 0);
    assert(errors.every((error) => error === failure));
  } finally {
    await server.close();
  }
});

Deno.test("node listener answers 400 for an invalid request target", async () => {
  let called = false;
  const server = await serve(() => {
    called = true;
    return new Response(null);
  });
  try {
    const port = Number(new URL(server.origin).port);
    const status = await new Promise<string>((resolve, reject) => {
      let data = "";
      const socket = connect(port, "127.0.0.1", () => {
        socket.write(
          "GET / HTTP/1.1\r\nHost: [invalid\r\nConnection: close\r\n\r\n",
        );
      });
      socket.setEncoding("utf8");
      socket.on("data", (chunk) => data += chunk);
      socket.on("end", () => resolve(data.split("\r\n")[0]));
      socket.on("error", reject);
    });
    assertEquals(status, "HTTP/1.1 400 Bad Request");
    assertEquals(called, false);
  } finally {
    await server.close();
  }
});

Deno.test("node listener aborts the request when the client disconnects", async () => {
  const errors: unknown[] = [];
  let started!: () => void;
  const handlerStarted = new Promise<void>((resolve) => started = resolve);
  let aborted!: () => void;
  const requestAborted = new Promise<void>((resolve) => aborted = resolve);
  const server = await serve((request) => {
    request.signal.addEventListener("abort", () => aborted());
    started();
    return new Promise<Response>((_, reject) =>
      request.signal.addEventListener(
        "abort",
        () => reject(request.signal.reason),
      )
    );
  }, { onError: (error) => errors.push(error) });
  try {
    const controller = new AbortController();
    const pending = fetch(`${server.origin}/`, { signal: controller.signal })
      .catch(() => {});
    await handlerStarted;
    controller.abort();
    await pending;
    await requestAborted;
    assertEquals(errors, []);
  } finally {
    await server.close();
  }
});
