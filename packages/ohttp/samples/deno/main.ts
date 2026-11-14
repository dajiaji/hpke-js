import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createChunkedEncoding,
  createOhttpClient,
  createOhttpGateway,
  createOhttpHandler,
  type KdfAeadPair,
  type OhttpClient,
  type OhttpEncoding,
  ohttpFetch,
  type OhttpGateway,
} from "@hpke/ohttp";

/** JSON payload returned by the target in this example. */
interface Greeting {
  message: string;
  method: string;
  path: string;
}

type FetchHandler = (request: Request) => Promise<Response>;

/** Fetch a JSON resource through OHTTP and return it as `T`. */
async function fetchJson<T>(
  client: OhttpClient,
  url: string | URL,
  init?: RequestInit,
): Promise<T> {
  const response = await ohttpFetch(client, url, init);
  if (!response.ok) {
    throw new Error(`Target returned HTTP ${response.status}`);
  }
  return await response.json() as T;
}

const kem = new DhkemX25519HkdfSha256();
const suite: KdfAeadPair = { kdf: new HkdfSha256(), aead: new Aes128Gcm() };
const encoding: OhttpEncoding = createChunkedEncoding();

const gateway: OhttpGateway = createOhttpGateway({
  keyId: 1,
  kem,
  ...(await kem.generateKeyPair()),
  kdfAeadPairs: [suite],
  encoding,
});
const client: OhttpClient = createOhttpClient({
  kem,
  ...suite,
  encoding,
  keyConfig: await gateway.publicKeyConfig,
  relayUrl: "https://relay.example/ohttp",
});
const handle: FetchHandler = createOhttpHandler({
  gateway,
  forward(request: Request): Promise<Response> {
    const greeting: Greeting = {
      message: "Hello, OHTTP!",
      method: request.method,
      path: new URL(request.url).pathname,
    };
    return Promise.resolve(Response.json(greeting));
  },
});

// In-memory relay for this self-contained example. In production, use the
// real fetch implementation and configure a deployed relay URL.
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => handle(new Request(input, init));
try {
  const greeting = await fetchJson<Greeting>(
    client,
    "https://origin.example/hello",
  );
  console.log(`${greeting.method} ${greeting.path}: ${greeting.message}`);
} finally {
  globalThis.fetch = realFetch;
}
