import { expect, test } from "bun:test";

import {
  Aes128Gcm,
  Aes256Gcm,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import { createOhttpClient, createOhttpGateway } from "@hpke/ohttp";
import { createStandardEncoding } from "@hpke/ohttp/standard";

import type { AeadInterface, KdfInterface, KemInterface } from "@hpke/common";

async function setupGateway(
  params: Omit<
    import("@hpke/ohttp").OhttpGatewayParams,
    "privateKey" | "publicKey" | "encoding"
  >,
) {
  const keys = await params.kem.generateKeyPair();
  return createOhttpGateway({
    ...params,
    ...keys,
    encoding: createStandardEncoding(),
  });
}

async function testRoundtrip(
  kem: KemInterface,
  kdf: KdfInterface,
  aead: AeadInterface,
  label: string,
) {
  const server = await setupGateway({
    keyId: 0x01,
    kem,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const keyConfig = await server.publicKeyConfig;
  const client = createOhttpClient({
    encoding: createStandardEncoding(),
    kem,
    kdf,
    aead,
    keyConfig,
    relayUrl: "https://relay.example/ohttp",
  });
  const targetReq = [new TextEncoder().encode("hello world!")];
  const clientCtx = await client.encapsulateRequest(targetReq);
  const serverCtx = await server.decapsulateRequest(clientCtx.body);
  const body = await new Response(serverCtx.body).text();
  expect(body).toBe("hello world!");

  const encRes = await serverCtx.encapsulateResponse(
    [new TextEncoder().encode(label + " ok")],
  );
  const res = await clientCtx.decapsulateResponse(encRes.body);
  expect(await new Response(res).text()).toBe(label + " ok");
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
