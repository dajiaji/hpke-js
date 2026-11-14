import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import {
  Aes128Gcm,
  Aes256Gcm,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import { createOhttpClient, createOhttpGateway, OhttpError } from "../mod.ts";
import {
  createChunkedEncoding,
  createOhttpGatewayHandler,
  createStandardEncoding,
  ohttpFetch,
} from "../mod.ts";
import { collect, fragments, stream } from "../src/streams.ts";

for (const createEncoding of [createStandardEncoding, createChunkedEncoding]) {
  const encoding = createEncoding();
  for (const kem of [new DhkemX25519HkdfSha256(), new DhkemP256HkdfSha256()]) {
    for (const aead of [new Aes128Gcm(), new Aes256Gcm()]) {
      Deno.test(`${encoding.requestContentType} / KEM ${kem.id} / AEAD ${aead.id}`, async () => {
        const keys = await kem.generateKeyPair();
        const kdf = new HkdfSha256();
        const gateway = createOhttpGateway({
          keyId: 42,
          kem,
          ...keys,
          encoding,
          kdfAeadPairs: [{ kdf, aead: new Aes128Gcm() }, {
            kdf,
            aead: new Aes256Gcm(),
          }],
        });
        const client = createOhttpClient({
          kem,
          kdf,
          aead,
          encoding,
          keyConfig: await gateway.publicKeyConfig,
        });
        const data = new Uint8Array(40000).fill(123);
        const ctx = await client.encapsulateRequest(stream(fragments([data])));
        assertEquals(ctx.contentType, encoding.requestContentType);
        const received = await gateway.decapsulateRequest(ctx.body);
        assertEquals(await collect(received.body), data);
        const response = await received.encapsulateResponse([data]);
        assertEquals(response.contentType, encoding.responseContentType);
        assertEquals(
          await collect(await ctx.decapsulateResponse(response.body)),
          data,
        );
        await assertRejects(async () =>
          collect(await ctx.decapsulateResponse([]))
        );
        await assertRejects(async () =>
          collect((await received.encapsulateResponse([])).body)
        );
      });
    }
  }

  Deno.test(`${encoding.requestContentType}: fetch arguments, streaming response, signal`, async () => {
    const kem = new DhkemX25519HkdfSha256();
    const kdf = new HkdfSha256();
    const aead = new Aes128Gcm();
    const keys = await kem.generateKeyPair();
    const gateway = createOhttpGateway({
      keyId: 1,
      kem,
      ...keys,
      encoding,
      kdfAeadPairs: [{ kdf, aead }],
    });
    const client = createOhttpClient({
      kem,
      kdf,
      aead,
      encoding,
      keyConfig: await gateway.publicKeyConfig,
      relayUrl: "https://relay.example/ohttp",
    });
    let receivedSignal: AbortSignal | undefined;
    const handler = createOhttpGatewayHandler({
      gateway,
      async forward(request) {
        assertEquals(request.method, "POST");
        assertEquals(request.url, "https://target.example/api?q=1");
        assertEquals(request.headers.get("x-test"), "request");
        assertEquals(await request.text(), "secret payload");
        return new Response(
          stream(
            fragments([
              new TextEncoder().encode("first"),
              new TextEncoder().encode("second"),
            ]),
          ),
          {
            status: 201,
            headers: { "x-test": "response" },
          },
        );
      },
    });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (input, init) => {
      const request = new Request(input, init);
      assertEquals(request.url, client.relayUrl);
      assertEquals(
        request.headers.get("Content-Type"),
        encoding.requestContentType,
      );
      assertEquals(request.headers.get("Accept"), encoding.responseContentType);
      assertEquals(
        request.headers.get("Incremental"),
        encoding.incremental ? "?1" : null,
      );
      receivedSignal = init?.signal ?? undefined;
      return handler(request);
    };
    try {
      const controller = new AbortController();
      const response = await ohttpFetch(
        client,
        new Request("https://target.example/api?q=1"),
        {
          method: "POST",
          headers: { "x-test": "request" },
          body: "secret payload",
          signal: controller.signal,
        },
      );
      assertEquals(response.status, 201);
      assertEquals(response.headers.get("x-test"), "response");
      assertEquals(await response.text(), "firstsecond");
      controller.abort();
      assert(receivedSignal?.aborted);
      await assertRejects(() =>
        ohttpFetch(client, "https://target.example/", {
          signal: controller.signal,
        })
      );
      globalThis.fetch = () =>
        Promise.resolve(new Response(null, { status: 502 }));
      await assertRejects(
        () => ohttpFetch(client, "https://target.example/"),
        OhttpError,
        "Relay returned HTTP 502",
      );
      globalThis.fetch = () =>
        Promise.resolve(
          new Response("invalid", {
            headers: { "Content-Type": "text/plain" },
          }),
        );
      await assertRejects(
        () => ohttpFetch(client, "https://target.example/"),
        OhttpError,
        "Unexpected OHTTP response",
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
    assertEquals(
      (await handler(new Request("https://gateway.example/"))).status,
      405,
    );
    assertEquals(
      (await handler(
        new Request("https://gateway.example/", {
          method: "POST",
          body: "wrong",
        }),
      )).status,
      415,
    );
  });
}

Deno.test("client validates configuration without selecting primitives", async () => {
  const kem = new DhkemX25519HkdfSha256();
  const keys = await kem.generateKeyPair();
  const kdf = new HkdfSha256();
  const aead = new Aes128Gcm();
  const encoding = createStandardEncoding();
  const gateway = createOhttpGateway({
    keyId: 1,
    kem,
    ...keys,
    encoding,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const keyConfig = await gateway.publicKeyConfig;
  const client = createOhttpClient({ kem, kdf, aead, encoding, keyConfig });
  await assertRejects(
    () => ohttpFetch(client, "https://target.example"),
    OhttpError,
    "relayUrl",
  );
  assertThrows(
    () =>
      createOhttpClient({
        kem: new DhkemP256HkdfSha256(),
        kdf,
        aead,
        encoding,
        keyConfig,
      }),
    OhttpError,
    "KEM mismatch",
  );
  assertThrows(
    () =>
      createOhttpClient({
        kem,
        kdf,
        aead: new Aes256Gcm(),
        encoding,
        keyConfig,
      }),
    OhttpError,
    "KDF/AEAD",
  );
  assertThrows(
    () =>
      createOhttpGateway({
        keyId: 1,
        kem,
        ...keys,
        encoding,
        kdfAeadPairs: [],
      }),
    OhttpError,
  );
  await assertRejects(() => gateway.decapsulateRequest([new Uint8Array(3)]));
});

Deno.test("key rotation selects the first complete matching suite and validates key IDs", async () => {
  const x = new DhkemX25519HkdfSha256();
  const p = new DhkemP256HkdfSha256();
  const kdf = new HkdfSha256();
  const aead = new Aes128Gcm();
  const xKeys = await x.generateKeyPair();
  const pKeys = await p.generateKeyPair();
  const encoding = createStandardEncoding();
  const gateway = createOhttpGateway({
    kem: x,
    ...xKeys,
    keyId: 42,
    encoding,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const wrongKem = createOhttpGateway({
    kem: p,
    ...pKeys,
    keyId: 1,
    encoding,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const wrongAead = createOhttpGateway({
    kem: x,
    ...xKeys,
    keyId: 2,
    encoding,
    kdfAeadPairs: [{ kdf, aead: new Aes256Gcm() }],
  });
  const laterMatch = createOhttpGateway({
    kem: x,
    ...xKeys,
    keyId: 43,
    encoding,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const { concat, collect } = await import("../src/streams.ts");
  const client = createOhttpClient({
    kem: x,
    kdf,
    aead,
    encoding,
    keyConfig: concat([
      await wrongKem.publicKeyConfig,
      await wrongAead.publicKeyConfig,
      await gateway.publicKeyConfig,
      await laterMatch.publicKeyConfig,
    ]),
  });
  const exchange = await client.encapsulateRequest([new Uint8Array([7])]);
  const wire = await collect(exchange.body);
  assertEquals(wire[0], 42);
  assertEquals(
    await collect((await gateway.decapsulateRequest([wire])).body),
    new Uint8Array([7]),
  );
  const { serializeKeyConfig, deserializeKeyConfig } = await import(
    "../mod.ts"
  );
  const parsed = deserializeKeyConfig(await gateway.publicKeyConfig)[0];
  for (const keyId of [-1, 256, 1.5, NaN]) {
    assertThrows(
      () =>
        createOhttpGateway({
          kem: x,
          ...xKeys,
          keyId,
          encoding,
          kdfAeadPairs: [{ kdf, aead }],
        }),
      OhttpError,
      "keyId",
    );
    assertThrows(
      () =>
        createOhttpClient({
          kem: x,
          kdf,
          aead,
          encoding,
          keyConfig: { ...parsed, keyId },
        }),
      OhttpError,
      "keyId",
    );
    assertThrows(
      () => serializeKeyConfig({ ...parsed, keyId }),
      OhttpError,
      "keyId",
    );
  }
});
