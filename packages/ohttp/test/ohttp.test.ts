import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  Aes128Gcm,
  Aes256Gcm,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { OhttpClient, OhttpServer } from "../mod.ts";

const x25519 = new DhkemX25519HkdfSha256();
const p256 = new DhkemP256HkdfSha256();
const sha256 = new HkdfSha256();
const aes128gcm = new Aes128Gcm();
const aes256gcm = new Aes256Gcm();

describe("OHTTP", () => {
  describe("Client/Server roundtrip (X25519, HKDF-SHA256, AES-128-GCM)", () => {
    it("should encapsulate and decapsulate a GET request", async () => {
      const server = await OhttpServer.setup({
        keyId: 0x01,
        kem: x25519,
        kdfAeadPairs: [{ kdf: sha256, aead: aes128gcm }],
      });

      const keyConfig = await server.publicKeyConfig;

      const client = new OhttpClient({
        kem: x25519,
        kdf: sha256,
        aead: aes128gcm,
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/api", {
        method: "GET",
      });

      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);

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
      const server = await OhttpServer.setup({
        keyId: 0x42,
        kem: x25519,
        kdfAeadPairs: [{ kdf: sha256, aead: aes128gcm }],
      });

      const keyConfig = await server.publicKeyConfig;
      const client = new OhttpClient({
        kem: x25519,
        kdf: sha256,
        aead: aes128gcm,
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: "value" }),
      });

      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);

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
      const server = await OhttpServer.setup({
        keyId: 0x01,
        kem: x25519,
        kdfAeadPairs: [{ kdf: sha256, aead: aes256gcm }],
      });

      const keyConfig = await server.publicKeyConfig;
      const client = new OhttpClient({
        kem: x25519,
        kdf: sha256,
        aead: aes256gcm,
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/test");
      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("AES-256-GCM works"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "AES-256-GCM works");
    });
  });

  describe("Client/Server with multiple cipher suites", () => {
    it("client selects AES-128-GCM from server offering both", async () => {
      const server = await OhttpServer.setup({
        keyId: 0x01,
        kem: x25519,
        kdfAeadPairs: [
          { kdf: sha256, aead: aes128gcm },
          { kdf: sha256, aead: aes256gcm },
        ],
      });

      const keyConfig = await server.publicKeyConfig;
      const client = new OhttpClient({
        kem: x25519,
        kdf: sha256,
        aead: aes128gcm,
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const clientCtx = await client.encapsulateRequest(
        new Request("https://target.example/multi"),
      );
      const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("multi-suite"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "multi-suite");
    });

    it("client selects AES-256-GCM from server offering both", async () => {
      const server = await OhttpServer.setup({
        keyId: 0x01,
        kem: x25519,
        kdfAeadPairs: [
          { kdf: sha256, aead: aes128gcm },
          { kdf: sha256, aead: aes256gcm },
        ],
      });

      const keyConfig = await server.publicKeyConfig;
      const client = new OhttpClient({
        kem: x25519,
        kdf: sha256,
        aead: aes256gcm,
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const clientCtx = await client.encapsulateRequest(
        new Request("https://target.example/multi256"),
      );
      const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("aes256 selected"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "aes256 selected");
    });
  });

  describe("Client/Server roundtrip (P-256, HKDF-SHA256, AES-128-GCM)", () => {
    it("should work with DHKEM(P-256)", async () => {
      const server = await OhttpServer.setup({
        keyId: 0x01,
        kem: p256,
        kdfAeadPairs: [{ kdf: sha256, aead: aes128gcm }],
      });

      const keyConfig = await server.publicKeyConfig;
      const client = new OhttpClient({
        kem: p256,
        kdf: sha256,
        aead: aes128gcm,
        keyConfig,
        relayUrl: "https://relay.example/ohttp",
      });

      const targetRequest = new Request("https://target.example/p256");
      const clientCtx = await client.encapsulateRequest(targetRequest);
      const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);

      const encResponse = await serverCtx.encapsulateResponse(
        new Response("P-256 works"),
      );
      const response = await clientCtx.decapsulateResponse(encResponse);
      assertEquals(await response.text(), "P-256 works");
    });
  });
});
