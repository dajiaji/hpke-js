import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { createOhttpClient, createOhttpGateway } from "@hpke/ohttp";
import { createChunkedEncoding } from "@hpke/ohttp/chunked";
import { createOhttpHandler, ohttpFetch } from "@hpke/ohttp/http";

const kem = new DhkemX25519HkdfSha256();
const keys = await kem.generateKeyPair();
const kdf = new HkdfSha256();
const aead = new Aes128Gcm();
const encoding = createChunkedEncoding();
const gateway = createOhttpGateway({
  keyId: 1,
  kem,
  ...keys,
  kdfAeadPairs: [{ kdf, aead }],
  encoding,
});
const client = createOhttpClient({
  kem,
  kdf,
  aead,
  encoding,
  keyConfig: await gateway.publicKeyConfig,
  relayUrl: "https://relay.example/ohttp",
});
const handle = createOhttpHandler({
  gateway,
  forward(request) {
    console.log(request.method, request.url);
    return Promise.resolve(new Response("Hello, OHTTP!"));
  },
});

// In-memory relay for this self-contained example. In production, use the
// real fetch implementation and configure a deployed relay URL.
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => handle(new Request(input, init));
try {
  const response = await ohttpFetch(client, "https://origin.example/hello");
  console.log(await response.text());
} finally {
  globalThis.fetch = realFetch;
}
