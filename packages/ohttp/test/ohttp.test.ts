import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  Aes128Gcm,
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  DhkemX25519HkdfSha256,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
} from "@hpke/core";

import {
  createOhttpClient,
  createOhttpServer,
  deserializeKeyConfig,
  type OhttpClient,
  OhttpError,
  type OhttpServer,
} from "../mod.ts";

const x25519 = new DhkemX25519HkdfSha256();
const p256 = new DhkemP256HkdfSha256();
const sha256 = new HkdfSha256();
const aes128gcm = new Aes128Gcm();
const aes256gcm = new Aes256Gcm();

async function createClientAndServer() {
  const server = await createOhttpServer({
    keyId: 0x23,
    kem: x25519,
    suites: [{ kdf: sha256, aead: aes128gcm }],
  });
  const client = await createOhttpClient({
    kem: x25519,
    suites: [{ kdf: sha256, aead: aes128gcm }],
    keyConfig: server.keyConfig,
    relayUrl: "https://relay.example/ohttp",
  });
  return { client, server };
}

describe("OHTTP", () => {
  describe("client fetch", () => {
    it("sends an encapsulated POST to the relay and returns the decrypted response", async () => {
      const { client, server } = await createClientAndServer();
      const originalFetch = globalThis.fetch;
      let relayRequest: Request | undefined;
      globalThis.fetch = async (input, init) => {
        relayRequest = new Request(input, init);
        const encapsulatedBytes = new Uint8Array(
          await relayRequest.arrayBuffer(),
        );
        const relayBody = new TextDecoder().decode(encapsulatedBytes);
        assertEquals(relayBody.includes("secret payload"), false);
        assertEquals(relayBody.includes("target.example"), false);
        const serverContext = await server.decapsulateRequest(
          encapsulatedBytes,
        );
        assertEquals(serverContext.request.method, "POST");
        assertEquals(new URL(serverContext.request.url).pathname, "/target");
        assertEquals(await serverContext.request.text(), "secret payload");
        const encryptedResponse = await serverContext.encapsulateResponse(
          new Response("decrypted response", { status: 201 }),
        );
        return new Response(encryptedResponse.slice().buffer as ArrayBuffer, {
          status: 200,
        });
      };

      try {
        const response = await client.fetch(
          new Request("https://target.example/target", {
            method: "POST",
            body: "secret payload",
          }),
        );
        assertEquals(relayRequest?.url, "https://relay.example/ohttp");
        assertEquals(relayRequest?.method, "POST");
        assertEquals(
          relayRequest?.headers.get("Content-Type"),
          "message/ohttp-req",
        );
        assertEquals(response.status, 201);
        assertEquals(await response.text(), "decrypted response");
      } finally {
        globalThis.fetch = originalFetch;
      }
    });

    it("reports non-success relay responses", async () => {
      const { client } = await createClientAndServer();
      const originalFetch = globalThis.fetch;
      globalThis.fetch = () =>
        Promise.resolve(new Response(null, { status: 502 }));
      try {
        await assertRejects(
          () =>
            client.fetch("https://target.example/", {
              method: "POST",
              body: "payload",
            }),
          OhttpError,
          "Relay returned HTTP 502",
        );
        await assertRejects(
          () =>
            client.fetch(new Request("https://target.example/"), {
              method: "POST",
              body: "payload",
            }),
          OhttpError,
          "Relay returned HTTP 502",
        );
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  describe("Client/Server roundtrip (X25519, HKDF-SHA256, AES-128-GCM)", () => {
    it("should encapsulate and decapsulate a GET request", async () => {
      const server = await createOhttpServer({
        keyId: 0x01,
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      });

      const keyConfig = server.keyConfig;

      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/api", {
        method: "GET",
      });

      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(
        clientCtx.encapsulatedRequest,
      );

      assertEquals(serverCtx.request.method, "GET");
      assertEquals(new URL(serverCtx.request.url).pathname, "/api");

      const targetResponse = new Response("Hello OHTTP", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });

      const encResponse = await serverCtx.encapsulateResponse(targetResponse);
      const response = await clientCtx.decapsulateResponse(encResponse);

      assertEquals(response.status, 200);
      assertEquals(await response.text(), "Hello OHTTP");
    });

    it("should encapsulate and decapsulate a POST request with body", async () => {
      const server = await createOhttpServer({
        keyId: 0x42,
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      });

      const keyConfig = server.keyConfig;
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: "value" }),
      });

      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(
        clientCtx.encapsulatedRequest,
      );

      assertEquals(serverCtx.request.method, "POST");
      const body = await serverCtx.request.json();
      assertEquals(body.key, "value");

      const targetResponse = new Response(
        JSON.stringify({ status: "ok" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );

      const encResponse = await serverCtx.encapsulateResponse(targetResponse);
      const response = await clientCtx.decapsulateResponse(encResponse);

      assertEquals(response.status, 200);
      const resBody = await response.json();
      assertEquals(resBody.status, "ok");
    });
  });

  describe("Client/Server roundtrip (X25519, HKDF-SHA256, AES-256-GCM)", () => {
    it("should work with AES-256-GCM", async () => {
      const server = await createOhttpServer({
        keyId: 0x01,
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes256gcm }],
      });

      const keyConfig = server.keyConfig;
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes256gcm }],
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/test");
      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(
        clientCtx.encapsulatedRequest,
      );

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("AES-256-GCM works"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "AES-256-GCM works");
    });
  });

  describe("Client/Server with multiple cipher suites", () => {
    it("client selects AES-128-GCM from server offering both", async () => {
      const server = await createOhttpServer({
        keyId: 0x01,
        kem: x25519,
        suites: [
          { kdf: sha256, aead: aes128gcm },
          { kdf: sha256, aead: aes256gcm },
        ],
      });

      const keyConfig = server.keyConfig;
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const clientCtx = await client.encapsulateRequest(
        new Request("https://target.example/multi"),
      );
      const serverCtx = await server.decapsulateRequest(
        clientCtx.encapsulatedRequest,
      );

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("multi-suite"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "multi-suite");
    });

    it("client selects AES-256-GCM from server offering both", async () => {
      const server = await createOhttpServer({
        keyId: 0x01,
        kem: x25519,
        suites: [
          { kdf: sha256, aead: aes128gcm },
          { kdf: sha256, aead: aes256gcm },
        ],
      });

      const keyConfig = server.keyConfig;
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes256gcm }],
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const clientCtx = await client.encapsulateRequest(
        new Request("https://target.example/multi256"),
      );
      const serverCtx = await server.decapsulateRequest(
        clientCtx.encapsulatedRequest,
      );

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("aes256 selected"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "aes256 selected");
    });
  });

  describe("Client/Server roundtrip (P-256, HKDF-SHA256, AES-128-GCM)", () => {
    it("should work with DHKEM(P-256)", async () => {
      const server = await createOhttpServer({
        keyId: 0x01,
        kem: p256,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      });

      const keyConfig = server.keyConfig;
      const client = await createOhttpClient({
        kem: p256,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/p256");
      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(
        clientCtx.encapsulatedRequest,
      );

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("P-256 works"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "P-256 works");
    });
  });

  describe("createOhttpServer", () => {
    it("exposes the key configuration synchronously", async () => {
      const server = await createOhttpServer({
        keyId: 0x7f,
        kem: x25519,
        suites: [
          { kdf: sha256, aead: aes256gcm },
          { kdf: sha256, aead: aes128gcm },
        ],
      });
      const configs = deserializeKeyConfig(server.keyConfig);
      assertEquals(configs.length, 1);
      assertEquals(configs[0].keyId, 0x7f);
      assertEquals(configs[0].kem, x25519.id);
      assertEquals(configs[0].publicKey.byteLength, 32);
      // Suites are advertised in the given order of preference.
      assertEquals(configs[0].cipherSuites, [
        { kdf: sha256.id, aead: aes256gcm.id },
        { kdf: sha256.id, aead: aes128gcm.id },
      ]);
    });

    it("uses an existing key pair", async () => {
      const keyPair = await x25519.generateKeyPair();
      const params = {
        keyId: 1,
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyPair,
      };
      const a = await createOhttpServer(params);
      const b = await createOhttpServer(params);
      assertEquals(a.keyConfig, b.keyConfig);
      assertEquals(
        deserializeKeyConfig(a.keyConfig)[0].publicKey,
        new Uint8Array(await x25519.serializePublicKey(keyPair.publicKey)),
      );

      // A request encapsulated for one instance is readable by the other.
      const client = await createOhttpClient({
        kem: x25519,
        suites: params.suites,
        keyConfig: a.keyConfig,
      });
      const ctx = await client.encapsulateRequest(
        new Request("https://target.example/shared"),
      );
      const { request } = await b.decapsulateRequest(ctx.encapsulatedRequest);
      assertEquals(request.url, "https://target.example/shared");
    });

    it("generates a distinct key pair by default", async () => {
      const params = {
        keyId: 1,
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      };
      const a = await createOhttpServer(params);
      const b = await createOhttpServer(params);
      assertEquals(bytesEqual(a.keyConfig, b.keyConfig), false);
    });

    it("rejects invalid parameters", async () => {
      const suites = [{ kdf: sha256, aead: aes128gcm }];
      for (const keyId of [-1, 256, 1.5, NaN]) {
        await assertRejects(
          () => createOhttpServer({ keyId, kem: x25519, suites }),
          OhttpError,
          "Invalid keyId",
        );
      }
      await assertRejects(
        () => createOhttpServer({ keyId: 1, kem: x25519, suites: [] }),
        OhttpError,
        "At least one KDF/AEAD pair",
      );
    });
  });

  describe("createOhttpClient", () => {
    it("accepts a parsed key configuration", async () => {
      const { server } = await createClientAndServer();
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig: deserializeKeyConfig(server.keyConfig)[0],
      });
      const ctx = await client.encapsulateRequest(
        new Request("https://target.example/parsed"),
      );
      const { request } = await server.decapsulateRequest(
        ctx.encapsulatedRequest,
      );
      assertEquals(request.url, "https://target.example/parsed");
    });

    it("selects the suite in the gateway's order of preference", async () => {
      const server = await createOhttpServer({
        keyId: 1,
        kem: x25519,
        suites: [
          { kdf: sha256, aead: aes256gcm },
          { kdf: sha256, aead: aes128gcm },
        ],
      });
      // The client lists AES-128-GCM first, but the gateway prefers
      // AES-256-GCM.
      const client = await createOhttpClient({
        kem: x25519,
        suites: [
          { kdf: sha256, aead: aes128gcm },
          { kdf: sha256, aead: aes256gcm },
        ],
        keyConfig: server.keyConfig,
      });
      const ctx = await client.encapsulateRequest(
        new Request("https://target.example/"),
      );
      const hdr = new DataView(ctx.encapsulatedRequest.buffer);
      assertEquals(hdr.getUint8(0), 1);
      assertEquals(hdr.getUint16(1), x25519.id);
      assertEquals(hdr.getUint16(3), sha256.id);
      assertEquals(hdr.getUint16(5), aes256gcm.id);
      await server.decapsulateRequest(ctx.encapsulatedRequest);
    });

    it("selects the first supported entry of multiple key configurations", async () => {
      const p256Server = await createOhttpServer({
        keyId: 1,
        kem: p256,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      });
      const x25519Server = await createOhttpServer({
        keyId: 2,
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      });
      const keyConfig = new Uint8Array([
        ...p256Server.keyConfig,
        ...x25519Server.keyConfig,
      ]);
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig,
      });
      const ctx = await client.encapsulateRequest(
        new Request("https://target.example/second"),
      );
      assertEquals(ctx.encapsulatedRequest[0], 2);
      const { request } = await x25519Server.decapsulateRequest(
        ctx.encapsulatedRequest,
      );
      assertEquals(request.url, "https://target.example/second");
    });

    it("rejects unsupported key configurations", async () => {
      const { server } = await createClientAndServer();
      const suites = [{ kdf: sha256, aead: aes128gcm }];
      await assertRejects(
        () =>
          createOhttpClient({ kem: p256, suites, keyConfig: server.keyConfig }),
        OhttpError,
        "KEM 0x10 not found",
      );
      await assertRejects(
        () =>
          createOhttpClient({
            kem: x25519,
            suites: [{ kdf: sha256, aead: aes256gcm }],
            keyConfig: server.keyConfig,
          }),
        OhttpError,
        "No mutually supported KDF/AEAD pair",
      );
      await assertRejects(
        () =>
          createOhttpClient({
            kem: x25519,
            suites: [],
            keyConfig: server.keyConfig,
          }),
        OhttpError,
        "At least one KDF/AEAD pair",
      );
      await assertRejects(
        () =>
          createOhttpClient({
            kem: x25519,
            suites,
            keyConfig: new Uint8Array(0),
          }),
        OhttpError,
        "Empty key configuration",
      );
      await assertRejects(
        () =>
          createOhttpClient({
            kem: x25519,
            suites,
            keyConfig: server.keyConfig.slice(0, 10),
          }),
        OhttpError,
      );
    });

    it("rejects an invalid public key", async () => {
      const server = await createOhttpServer({
        keyId: 1,
        kem: p256,
        suites: [{ kdf: sha256, aead: aes128gcm }],
      });
      const config = deserializeKeyConfig(server.keyConfig)[0];
      config.publicKey = new Uint8Array(65); // not a point on the curve
      await assertRejects(
        () =>
          createOhttpClient({
            kem: p256,
            suites: [{ kdf: sha256, aead: aes128gcm }],
            keyConfig: config,
          }),
        OhttpError,
        "Invalid public key",
      );
    });

    it("rejects an invalid relayUrl", async () => {
      const { server } = await createClientAndServer();
      await assertRejects(
        () =>
          createOhttpClient({
            kem: x25519,
            suites: [{ kdf: sha256, aead: aes128gcm }],
            keyConfig: server.keyConfig,
            relayUrl: "not a url",
          }),
        OhttpError,
        "Invalid relayUrl",
      );
    });

    it("requires relayUrl only for fetch()", async () => {
      const { server } = await createClientAndServer();
      const client = await createOhttpClient({
        kem: x25519,
        suites: [{ kdf: sha256, aead: aes128gcm }],
        keyConfig: server.keyConfig,
      });
      await client.encapsulateRequest(new Request("https://target.example/"));
      await assertRejects(
        () => client.fetch("https://target.example/"),
        OhttpError,
        "relayUrl is required",
      );
    });
  });

  describe("shared primitive instances", () => {
    /** Round-trips a request and a response between `client` and `server`. */
    async function roundtrip(
      client: OhttpClient,
      server: OhttpServer,
      aeadId: number,
    ): Promise<void> {
      const ctx = await client.encapsulateRequest(
        new Request("https://target.example/shared", {
          method: "POST",
          body: "request body",
        }),
      );
      const hdr = new DataView(ctx.encapsulatedRequest.buffer);
      assertEquals(hdr.getUint16(5), aeadId);
      const serverCtx = await server.decapsulateRequest(
        ctx.encapsulatedRequest,
      );
      assertEquals(await serverCtx.request.text(), "request body");
      const response = await ctx.decapsulateResponse(
        await serverCtx.encapsulateResponse(new Response("response body")),
      );
      assertEquals(await response.text(), "response body");
    }

    it("serves every advertised suite when the suites share a KDF instance", async () => {
      const kdf = new HkdfSha256();
      const aeads = [new Aes128Gcm(), new Aes256Gcm()];
      const server = await createOhttpServer({
        keyId: 1,
        kem: new DhkemX25519HkdfSha256(),
        suites: aeads.map((aead) => ({ kdf, aead })),
      });
      // Clients use their own primitive instances, independent of the
      // gateway's and of each other.
      for (const aead of [new Aes128Gcm(), new Aes256Gcm()]) {
        const client = await createOhttpClient({
          kem: new DhkemX25519HkdfSha256(),
          suites: [{ kdf: new HkdfSha256(), aead }],
          keyConfig: server.keyConfig,
        });
        await roundtrip(client, server, aead.id);
      }
    });

    it("serves every advertised suite with other shared KDFs", async () => {
      const cases = [
        { kem: () => new DhkemP384HkdfSha384(), kdf: () => new HkdfSha384() },
        { kem: () => new DhkemP521HkdfSha512(), kdf: () => new HkdfSha512() },
      ];
      for (const c of cases) {
        const kdf = c.kdf();
        const server = await createOhttpServer({
          keyId: 1,
          kem: c.kem(),
          suites: [
            { kdf, aead: new Aes128Gcm() },
            { kdf, aead: new Aes256Gcm() },
          ],
        });
        for (const aead of [new Aes128Gcm(), new Aes256Gcm()]) {
          const client = await createOhttpClient({
            kem: c.kem(),
            suites: [{ kdf: c.kdf(), aead }],
            keyConfig: server.keyConfig,
          });
          await roundtrip(client, server, aead.id);
        }
      }
    });

    it("keeps clients sharing a KDF instance independent", async () => {
      const serverFor = (aead: Aes128Gcm | Aes256Gcm) =>
        createOhttpServer({
          keyId: 1,
          kem: new DhkemX25519HkdfSha256(),
          suites: [{ kdf: new HkdfSha256(), aead }],
        });
      const server128 = await serverFor(new Aes128Gcm());
      const server256 = await serverFor(new Aes256Gcm());

      const kem = new DhkemX25519HkdfSha256();
      const kdf = new HkdfSha256();
      const client128 = await createOhttpClient({
        kem,
        suites: [{ kdf, aead: new Aes128Gcm() }],
        keyConfig: server128.keyConfig,
      });
      const client256 = await createOhttpClient({
        kem,
        suites: [{ kdf, aead: new Aes256Gcm() }],
        keyConfig: server256.keyConfig,
      });
      // The client created first must not be affected by the second one.
      await roundtrip(client128, server128, aes128gcm.id);
      await roundtrip(client256, server256, aes256gcm.id);
      await roundtrip(client128, server128, aes128gcm.id);
    });

    it("does not modify the given KDF instance", async () => {
      const kem = new DhkemX25519HkdfSha256();
      const kdf = new HkdfSha256();
      // A cipher suite of the application that uses the same KDF instance.
      const appSuite = new CipherSuite({ kem, kdf, aead: new Aes128Gcm() });
      const keyPair = await kem.generateKeyPair();

      const server = await createOhttpServer({
        keyId: 1,
        kem,
        suites: [{ kdf, aead: new Aes256Gcm() }],
      });
      const client = await createOhttpClient({
        kem,
        suites: [{ kdf, aead: new Aes256Gcm() }],
        keyConfig: server.keyConfig,
      });
      await roundtrip(client, server, aes256gcm.id);

      // The application's suite still interoperates with an independent
      // suite of the same algorithms.
      const peerSuite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });
      const sender = await peerSuite.createSenderContext({
        recipientPublicKey: keyPair.publicKey,
      });
      const ct = await sender.seal(new TextEncoder().encode("app message"));
      const recipient = await appSuite.createRecipientContext({
        recipientKey: keyPair.privateKey,
        enc: sender.enc,
      });
      assertEquals(
        new TextDecoder().decode(await recipient.open(ct)),
        "app message",
      );
    });

    it("handles concurrent requests for different suites", async () => {
      const kdf = new HkdfSha256();
      const server = await createOhttpServer({
        keyId: 1,
        kem: new DhkemX25519HkdfSha256(),
        suites: [
          { kdf, aead: new Aes128Gcm() },
          { kdf, aead: new Aes256Gcm() },
        ],
      });
      const clients = await Promise.all(
        [new Aes128Gcm(), new Aes256Gcm()].map(async (aead) => ({
          aeadId: aead.id,
          client: await createOhttpClient({
            kem: new DhkemX25519HkdfSha256(),
            suites: [{ kdf: new HkdfSha256(), aead }],
            keyConfig: server.keyConfig,
          }),
        })),
      );
      await Promise.all(
        Array.from({ length: 20 }, (_, i) => {
          const { client, aeadId } = clients[i % 2];
          return roundtrip(client, server, aeadId);
        }),
      );
    });
  });

  describe("contexts", () => {
    it("can be destructured", async () => {
      const { client, server } = await createClientAndServer();
      const { encapsulatedRequest, decapsulateResponse } = await client
        .encapsulateRequest(new Request("https://target.example/d"));
      const { request, encapsulateResponse } = await server
        .decapsulateRequest(encapsulatedRequest);
      assertEquals(request.url, "https://target.example/d");
      const response = await decapsulateResponse(
        await encapsulateResponse(new Response("destructured")),
      );
      assertEquals(await response.text(), "destructured");
    });

    it("rejects a response encapsulated for another request", async () => {
      const { client, server } = await createClientAndServer();
      const req = () => new Request("https://target.example/");
      const c1 = await client.encapsulateRequest(req());
      const c2 = await client.encapsulateRequest(req());
      const s1 = await server.decapsulateRequest(c1.encapsulatedRequest);
      const encapsulatedResponse = await s1.encapsulateResponse(
        new Response("for c1"),
      );
      await assertRejects(() => c2.decapsulateResponse(encapsulatedResponse));
      const response = await c1.decapsulateResponse(encapsulatedResponse);
      assertEquals(await response.text(), "for c1");
    });
  });

  describe("server decapsulateRequest", () => {
    it("rejects malformed encapsulated requests", async () => {
      const { client, server } = await createClientAndServer();
      const { encapsulatedRequest } = await client.encapsulateRequest(
        new Request("https://target.example/"),
      );
      await assertRejects(
        () => server.decapsulateRequest(encapsulatedRequest.slice(0, 6)),
        OhttpError,
        "too short",
      );
      const wrongKeyId = encapsulatedRequest.slice();
      wrongKeyId[0] ^= 0xff;
      await assertRejects(
        () => server.decapsulateRequest(wrongKeyId),
        OhttpError,
        "Key ID mismatch",
      );
      const wrongSuite = encapsulatedRequest.slice();
      wrongSuite[6] = aes256gcm.id;
      await assertRejects(
        () => server.decapsulateRequest(wrongSuite),
        OhttpError,
        "Unsupported cipher suite",
      );
      const tampered = encapsulatedRequest.slice();
      tampered[tampered.length - 1] ^= 0x01;
      await assertRejects(() => server.decapsulateRequest(tampered));
    });
  });

  describe("server handle", () => {
    /** Routes the client's relay request directly to `server.handle()`. */
    async function withRelay<T>(
      server: OhttpServer,
      handler: (request: Request) => Response | Promise<Response>,
      f: () => Promise<T>,
    ): Promise<T> {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (input, init) =>
        server.handle(new Request(input, init), handler);
      try {
        return await f();
      } finally {
        globalThis.fetch = originalFetch;
      }
    }

    it("serves client.fetch() end to end", async () => {
      const { client, server } = await createClientAndServer();
      const response = await withRelay(
        server,
        async (request) => {
          assertEquals(request.method, "POST");
          assertEquals(request.url, "https://target.example/echo?x=1");
          assertEquals(request.headers.get("x-test"), "1");
          return new Response(`echo: ${await request.text()}`, {
            status: 201,
            headers: { "Content-Type": "text/plain", "X-Reply": "yes" },
          });
        },
        () =>
          client.fetch("https://target.example/echo?x=1", {
            method: "POST",
            headers: { "X-Test": "1" },
            body: "ping",
          }),
      );
      assertEquals(response.status, 201);
      assertEquals(response.headers.get("content-type"), "text/plain");
      assertEquals(response.headers.get("x-reply"), "yes");
      assertEquals(await response.text(), "echo: ping");
    });

    it("returns a message/ohttp-res response", async () => {
      const { client, server } = await createClientAndServer();
      const ctx = await client.encapsulateRequest(
        new Request("https://target.example/"),
      );
      const relayResponse = await server.handle(
        new Request("https://gateway.example/", {
          method: "POST",
          headers: { "Content-Type": "message/ohttp-req; charset=binary" },
          body: ctx.encapsulatedRequest.slice().buffer as ArrayBuffer,
        }),
        () => new Response("sync handler"),
      );
      assertEquals(relayResponse.status, 200);
      assertEquals(
        relayResponse.headers.get("content-type"),
        "message/ohttp-res",
      );
      const response = await ctx.decapsulateResponse(
        new Uint8Array(await relayResponse.arrayBuffer()),
      );
      assertEquals(await response.text(), "sync handler");
    });

    it("rejects requests that are not OHTTP requests", async () => {
      const { server } = await createClientAndServer();
      const handler = () => {
        throw new Error("must not be called");
      };
      const get = await server.handle(
        new Request("https://gateway.example/"),
        handler,
      );
      assertEquals(get.status, 405);
      assertEquals(get.headers.get("allow"), "POST");

      for (const contentType of ["text/plain", "message/ohttp-res", null]) {
        const res = await server.handle(
          new Request("https://gateway.example/", {
            method: "POST",
            headers: contentType ? { "Content-Type": contentType } : undefined,
            body: new Uint8Array(8),
          }),
          handler,
        );
        assertEquals(res.status, 415);
      }
    });

    it("rejects requests that cannot be decapsulated", async () => {
      const { client, server } = await createClientAndServer();
      const handler = () => {
        throw new Error("must not be called");
      };
      const { encapsulatedRequest } = await client.encapsulateRequest(
        new Request("https://target.example/"),
      );
      const post = (body: Uint8Array) =>
        server.handle(
          new Request("https://gateway.example/", {
            method: "POST",
            headers: { "Content-Type": "message/ohttp-req" },
            body: body.slice().buffer as ArrayBuffer,
          }),
          handler,
        );

      const tampered = encapsulatedRequest.slice();
      tampered[tampered.length - 1] ^= 0x01;
      for (const body of [new Uint8Array(0), tampered.slice(0, 5), tampered]) {
        const res = await post(body);
        assertEquals(res.status, 400);
        assertEquals(res.headers.get("content-type"), null);
      }

      // Unknown key identifier (RFC 9458 Section 5.3).
      const wrongKeyId = encapsulatedRequest.slice();
      wrongKeyId[0] ^= 0xff;
      const res = await post(wrongKeyId);
      assertEquals(res.status, 400);
      assertEquals(
        res.headers.get("content-type"),
        "application/problem+json",
      );
      assertEquals(
        (await res.json()).type,
        "https://iana.org/assignments/http-problem-types#ohttp-key",
      );
    });

    it("propagates errors thrown by the handler", async () => {
      const { client, server } = await createClientAndServer();
      const { encapsulatedRequest } = await client.encapsulateRequest(
        new Request("https://target.example/"),
      );
      await assertRejects(
        () =>
          server.handle(
            new Request("https://gateway.example/", {
              method: "POST",
              headers: { "Content-Type": "message/ohttp-req" },
              body: encapsulatedRequest.slice().buffer as ArrayBuffer,
            }),
            () => Promise.reject(new Error("target failed")),
          ),
        Error,
        "target failed",
      );
    });
  });
});

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.byteLength === b.byteLength && a.every((v, i) => v === b[i]);
}
