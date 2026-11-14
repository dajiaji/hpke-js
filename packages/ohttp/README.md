<h1 align="center">@hpke/ohttp</h1>

<div align="center">
<a href="https://www.npmjs.com/package/@hpke/ohttp"><img src="https://img.shields.io/npm/v/@hpke/ohttp" alt="npm"/></a>
<a href="https://jsr.io/@hpke/ohttp"><img src="https://jsr.io/badges/@hpke/ohttp" alt="JSR"/></a>
</div>

<div align="center">
An <a href="https://www.rfc-editor.org/rfc/rfc9458">Oblivious HTTP (OHTTP)</a>
client and gateway built on <a href="https://github.com/dajiaji/hpke-js/tree/main/packages/core">@hpke/core</a>.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/ohttp/doc) |
[Pages](https://dajiaji.github.io/hpke-js/ohttp/docs/)

</div>

This ESM package requires Node.js 20 or later. Cryptographic primitives and the
wire encoding are supplied explicitly, so unused encodings can be removed by
tree-shaking.

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
  - [Client](#client)
  - [Gateway](#gateway)
  - [Streaming](#streaming)
- [Contributing](#contributing)
- [References](#references)
- [License](#license)

## Installation

### Node.js

```sh
npm install @hpke/ohttp @hpke/core
```

### Deno

```sh
deno add jsr:@hpke/ohttp jsr:@hpke/core
```

### Web Browsers

Load the ESM package from a CDN such as [esm.sh](https://esm.sh/@hpke/ohttp).

## Usage

The standard encoding buffers complete messages. For incremental request and
response processing, use `createChunkedEncoding()` from the main entry point.

### Client

`ohttpFetch` mirrors `fetch`: its second argument and `RequestInit` options are
the same as the standard Fetch API. The gateway publishes its
`application/ohttp-keys` payload separately; the client fetches that payload
before creating an OHTTP client. In production, obtain this configuration
through the relay or another trusted distribution path so the gateway does not
learn the client's IP address during key retrieval.

```ts
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createOhttpClient,
  createStandardEncoding,
  ohttpFetch,
} from "@hpke/ohttp";

const keyConfigResponse = await fetch("https://gateway.example/ohttp-keys");
if (!keyConfigResponse.ok) {
  throw new Error(
    `Failed to fetch gateway key configuration: ${keyConfigResponse.status}`,
  );
}
const keyConfig = new Uint8Array(await keyConfigResponse.arrayBuffer());

const client = createOhttpClient({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
  keyConfig,
  encoding: createStandardEncoding(),
  relayUrl: "https://relay.example/ohttp",
});

const response = await ohttpFetch(client, "https://target.example/hello", {
  headers: { accept: "application/json" },
});
console.log(await response.text());
```

### Gateway

Use `createOhttpGatewayHandler` with the relay's Fetch request. The `forward`
callback receives the decrypted target request and decides how to answer it.
`createOhttpFetchForwarder` is a ready-made callback that fetches the target: it
answers 403 for origins outside `allowedOrigins`, returns redirects to the
client instead of following them, and removes the Content-Encoding and
Content-Length headers that no longer describe a decoded body.

The gateway does not decide how its key configuration is published.
`createOhttpKeyConfigHandler` is an independent handler that serves
`gateway.publicKeyConfig` as `application/ohttp-keys`; mount it on the same
service, on another trusted endpoint, or distribute the payload by other means.

Both handlers are plain `(request: Request) => Promise<Response>` functions, so
routing, authentication and other logic are composed around them:

```ts
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createOhttpFetchForwarder,
  createOhttpGateway,
  createOhttpGatewayHandler,
  createOhttpKeyConfigHandler,
  createStandardEncoding,
} from "@hpke/ohttp";

const kem = new DhkemX25519HkdfSha256();
const { privateKey, publicKey } = await kem.generateKeyPair();

const gateway = createOhttpGateway({
  keyId: 1,
  kem,
  privateKey,
  publicKey,
  kdfAeadPairs: [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }],
  encoding: createStandardEncoding(),
});

const ohttp = createOhttpGatewayHandler({
  gateway,
  forward: createOhttpFetchForwarder({
    allowedOrigins: ["https://target.example"],
  }),
});
const keys = createOhttpKeyConfigHandler(gateway);

export function handle(request: Request): Promise<Response> {
  const { pathname } = new URL(request.url);
  if (pathname === "/ohttp-keys") return keys(request);
  if (pathname === "/gateway") return ohttp(request);
  return Promise.resolve(new Response(null, { status: 404 }));
}
```

Runtimes with a Fetch-based server API can serve `handle` directly, for example
`Deno.serve(handle)`, `Bun.serve({ fetch: handle })` or
`export default { fetch: handle }` on Cloudflare Workers.

Node.js's `node:http` server does not use Fetch requests and responses, so wrap
`handle` with `toNodeListener` from the `@hpke/ohttp/node` entry point. It
streams request and response bodies and aborts the request's signal when the
client disconnects.

```ts
import { createServer } from "node:http";
import { toNodeListener } from "@hpke/ohttp/node";

// `handle` is the Fetch handler defined above.
import { handle } from "./handle.ts";

createServer(toNodeListener(handle, { onError: console.error })).listen(
  3000,
  () => console.log("OHTTP gateway listening on http://localhost:3000"),
);
```

### Streaming

Chunked encoding supports streaming uploads and incremental response reads when
the runtime and relay support streaming Fetch bodies. The gateway must use
`createChunkedEncoding()` as well when handling these requests.

```ts
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createChunkedEncoding,
  createOhttpClient,
  ohttpFetch,
} from "@hpke/ohttp";

const keyConfigResponse = await fetch("https://gateway.example/ohttp-keys");
if (!keyConfigResponse.ok) {
  throw new Error(
    `Failed to fetch gateway key configuration: ${keyConfigResponse.status}`,
  );
}
const keyConfig = new Uint8Array(await keyConfigResponse.arrayBuffer());

const client = createOhttpClient({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
  keyConfig,
  encoding: createChunkedEncoding(),
  relayUrl: "https://relay.example/ohttp",
  streamingUpload: true,
});

const response = await ohttpFetch(
  client,
  "https://target.example/upload",
  {
    method: "POST",
    body: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("streamed body"));
        controller.close();
      },
    }),
    duplex: "half",
  } as RequestInit,
);

await response.body?.pipeTo(
  new WritableStream({
    write(bytes) {
      console.log(bytes);
    },
  }),
);
```

Relay uploads are buffered by default; set `streamingUpload: true` only when the
runtime, relay and connection support streaming uploads. Chunked receivers limit
plaintext chunks to 16384 bytes by default; use
`createChunkedEncoding({ maxChunkSize })` to raise that bound when required.
Successful completion of the response body authenticates the final chunk.
Truncation or an AEAD failure can reject body reads (as `OhttpError`), while
cancelling the body stops processing without establishing finality. Outer
redirects are rejected by `ohttpFetch`.

For low-level relay integrations, use `client.encapsulateRequest()` and
`gateway.decapsulateRequest()` directly.

## Contributing

We welcome contributions, issue reports and feature suggestions.

## References

- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [RFC 9292: Binary Representation of HTTP Messages](https://www.rfc-editor.org/rfc/rfc9292.html)
- [Chunked Oblivious HTTP Messages, draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.html)

## License

MIT
