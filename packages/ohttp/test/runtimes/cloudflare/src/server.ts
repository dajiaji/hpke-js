import {
  Aes128Gcm,
  Aes256Gcm,
  DhkemP256HkdfSha256,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
import { OhttpClient, OhttpServer } from "@hpke/ohttp";

const x25519 = new DhkemX25519HkdfSha256();
const p256 = new DhkemP256HkdfSha256();
const sha256 = new HkdfSha256();
const aes128gcm = new Aes128Gcm();
const aes256gcm = new Aes256Gcm();

export async function testServer(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname !== "/test") {
    return new Response("ng: invalid path");
  }
  const testCase = url.searchParams.get("case");
  if (testCase === null) {
    return new Response("ng: invalid params");
  }

  try {
    switch (testCase) {
      case "x25519-aes128gcm": {
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
        const targetReq = new Request("https://target.example/api", {
          method: "POST",
          body: "hello world!",
        });
        const clientCtx = await client.encapsulateRequest(targetReq);
        const serverCtx = await server.decapsulateRequest(
          clientCtx.encRequest,
        );
        const body = await serverCtx.request.text();
        if (body !== "hello world!") {
          return new Response("ng: body mismatch");
        }
        const encRes = await serverCtx.encapsulateResponse(
          new Response("ok from server"),
        );
        const res = await clientCtx.decapsulateResponse(encRes);
        if ((await res.text()) !== "ok from server") {
          return new Response("ng: response mismatch");
        }
        break;
      }
      case "x25519-aes256gcm": {
        const server = await OhttpServer.setup({
          keyId: 0x02,
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
        const targetReq = new Request("https://target.example/api");
        const clientCtx = await client.encapsulateRequest(targetReq);
        const serverCtx = await server.decapsulateRequest(
          clientCtx.encRequest,
        );
        const encRes = await serverCtx.encapsulateResponse(
          new Response("aes-256-gcm ok"),
        );
        const res = await clientCtx.decapsulateResponse(encRes);
        if ((await res.text()) !== "aes-256-gcm ok") {
          return new Response("ng: response mismatch");
        }
        break;
      }
      case "p256-aes128gcm": {
        const server = await OhttpServer.setup({
          keyId: 0x03,
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
        const targetReq = new Request("https://target.example/api");
        const clientCtx = await client.encapsulateRequest(targetReq);
        const serverCtx = await server.decapsulateRequest(
          clientCtx.encRequest,
        );
        const encRes = await serverCtx.encapsulateResponse(
          new Response("p256 ok"),
        );
        const res = await clientCtx.decapsulateResponse(encRes);
        if ((await res.text()) !== "p256 ok") {
          return new Response("ng: response mismatch");
        }
        break;
      }
      default:
        return new Response("ng: unknown case");
    }
  } catch (e: unknown) {
    return new Response("ng: " + (e as Error).message);
  }
  return new Response("ok");
}
