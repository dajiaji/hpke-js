import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { createOhttpClient, createOhttpServer } from "@hpke/ohttp";

async function doOhttp() {
  const kem = new DhkemX25519HkdfSha256();
  const suites = [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }];

  // Gateway: a key pair is generated unless `keyPair` is given.
  const server = await createOhttpServer({ keyId: 1, kem, suites });

  // Client: `server.keyConfig` is the `application/ohttp-keys` payload
  // published by the gateway.
  const client = await createOhttpClient({
    kem,
    suites,
    keyConfig: server.keyConfig,
  });

  // Client: encrypt the request (message/ohttp-req).
  const { encapsulatedRequest, decapsulateResponse } = await client
    .encapsulateRequest(new Request("https://origin.example/hello"));

  // Gateway: decrypt the request and encrypt the response
  // (message/ohttp-res).
  const { request, encapsulateResponse } = await server.decapsulateRequest(
    encapsulatedRequest,
  );
  console.log(request.method, request.url);
  const encapsulatedResponse = await encapsulateResponse(
    new Response("Hello, OHTTP!"),
  );

  // Client: decrypt the response.
  const response = await decapsulateResponse(encapsulatedResponse);
  console.log(await response.text());
}

try {
  await doOhttp();
} catch (err) {
  console.error("OHTTP sample failed:", err);
}
