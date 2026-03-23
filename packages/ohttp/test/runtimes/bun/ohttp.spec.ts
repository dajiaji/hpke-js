import { expect, test } from "bun:test";

import {
  Aes128Gcm,
  Aes256Gcm,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import { OhttpClient, OhttpServer } from "@hpke/ohttp";

import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/common";

async function testRoundtrip(
  kem: KemInterface,
  kdf: KdfInterface,
  aead: AeadInterface,
  label: string,
) {
  const server = await OhttpServer.setup({
    keyId: 0x01,
    kem,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const keyConfig = await server.publicKeyConfig;
  const client = new OhttpClient({
    kem,
    kdf,
    aead,
    keyConfig,
    relayUrl: "https://relay.example/ohttp",
  });
  const targetReq = new Request("https://target.example/api", {
    method: "POST",
    body: "hello world!",
  });
  const clientCtx = await client.encapsulateRequest(targetReq);
  const serverCtx = await server.decapsulateRequest(clientCtx.encRequest);
  const body = await serverCtx.request.text();
  expect(body).toBe("hello world!");

  const encRes = await serverCtx.encapsulateResponse(
    new Response(label + " ok"),
  );
  const res = await clientCtx.decapsulateResponse(encRes);
  expect(await res.text()).toBe(label + " ok");
}

test("bun - OHTTP with X25519/HKDF-SHA256/AES-128-GCM", async () => {
  await testRoundtrip(
    new DhkemX25519HkdfSha256(),
    new HkdfSha256(),
    new Aes128Gcm(),
    "x25519-aes128gcm",
  );
});

test("bun - OHTTP with X25519/HKDF-SHA256/AES-256-GCM", async () => {
  await testRoundtrip(
    new DhkemX25519HkdfSha256(),
    new HkdfSha256(),
    new Aes256Gcm(),
    "x25519-aes256gcm",
  );
});

test("bun - OHTTP with P-256/HKDF-SHA256/AES-128-GCM", async () => {
  await testRoundtrip(
    new DhkemP256HkdfSha256(),
    new HkdfSha256(),
    new Aes128Gcm(),
    "p256-aes128gcm",
  );
});
