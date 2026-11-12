// Run explicitly: deno test --allow-net packages/ohttp/test/http.integration.ts
import { assertEquals } from "@std/assert";
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { createOhttpClient, createOhttpGateway } from "../mod.ts";
import {
  createChunkedEncoding,
  createOhttpHandler,
  createStandardEncoding,
  ohttpFetch,
} from "../mod.ts";

for (const encoding of [createStandardEncoding(), createChunkedEncoding()]) {
  for (const compressed of [false, true]) {
    Deno.test(
      encoding.requestContentType +
        ": forward to real HTTP/1.1 upstream, gzip=" + compressed,
      async () => {
        const payload = "upstream response".repeat(80);
        const zipped = new Uint8Array(
          await new Response(
            new Response(payload).body!.pipeThrough(
              new CompressionStream("gzip"),
            ),
          ).arrayBuffer(),
        );
        const upstream = Deno.serve(
          {
            hostname: "127.0.0.1",
            port: 0,
            onListen() {},
          },
          () =>
            compressed
              ? new Response(zipped, {
                headers: {
                  "content-encoding": "gzip",
                  "content-length": String(zipped.length),
                  "x-upstream": "preserved",
                },
              })
              : new Response(
                new ReadableStream<Uint8Array>({
                  start(controller) {
                    controller.enqueue(new TextEncoder().encode(payload));
                    controller.close();
                  },
                }),
                { headers: { "x-upstream": "preserved" } },
              ),
        );
        let relay: Deno.HttpServer<Deno.NetAddr> | undefined;
        try {
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
          let transferEncoding: string | null = null;
          const handle = createOhttpHandler({
            gateway,
            async forward(request) {
              const response = await fetch(request);
              transferEncoding = response.headers.get("transfer-encoding");
              if (compressed) {
                assertEquals(response.headers.get("content-encoding"), "gzip");
                assertEquals(
                  response.headers.get("content-length"),
                  String(zipped.length),
                );
              }
              const headers = new Headers(response.headers);
              headers.delete("content-encoding");
              headers.delete("content-length");
              return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers,
              });
            },
          });
          relay = Deno.serve(
            { hostname: "127.0.0.1", port: 0, onListen() {} },
            handle,
          );
          const client = createOhttpClient({
            kem,
            kdf,
            aead,
            encoding,
            keyConfig: await gateway.publicKeyConfig,
            relayUrl: `http://127.0.0.1:${relay.addr.port}/`,
          });
          const response = await ohttpFetch(
            client,
            `http://127.0.0.1:${upstream.addr.port}/`,
          );
          assertEquals(response.status, 200);
          assertEquals(await response.text(), payload);
          assertEquals(response.headers.get("content-encoding"), null);
          assertEquals(response.headers.get("content-length"), null);
          assertEquals(transferEncoding, compressed ? null : "chunked");
          assertEquals(response.headers.get("transfer-encoding"), null);
          assertEquals(response.headers.get("x-upstream"), "preserved");
        } finally {
          await relay?.shutdown();
          await upstream.shutdown();
        }
      },
    );
  }
}
