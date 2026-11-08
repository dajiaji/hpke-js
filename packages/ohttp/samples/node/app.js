import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { OhttpClient, OhttpServer } from "@hpke/ohttp";

async function doOhttp() {
  const kem = new DhkemX25519HkdfSha256();
  const kdf = new HkdfSha256();
  const aead = new Aes128Gcm();

  const server = await OhttpServer.setup({
    keyId: 1,
    kem,
    kdfAeadPairs: [{ kdf, aead }],
  });

  const client = new OhttpClient({
    kem,
    kdf,
    aead,
    keyConfig: await server.publicKeyConfig,
    relayUrl: "https://relay.example/",
  });

  const requestContext = await client.encapsulateRequest(
    new Request("https://origin.example/hello"),
  );
  const serverContext = await server.decapsulateRequest(
    requestContext.encRequest,
  );
  const encryptedResponse = await serverContext.encapsulateResponse(
    new Response("Hello, OHTTP!"),
  );
  const response = await requestContext.decapsulateResponse(encryptedResponse);

  console.log(await response.text());
}

try {
  await doOhttp();
} catch (err) {
  console.error("OHTTP sample failed:", err);
}
