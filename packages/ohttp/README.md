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

Use `createOhttpHandler` with the relay's Fetch request. The callback receives
the decrypted target request. Expose `gateway.publicKeyConfig` from the same
service (or another trusted endpoint) as the client's `application/ohttp-keys`
payload.

On Node.js 24 or later, you can run the following TypeScript example using
Node.js's built-in type stripping and Fetch API.

```ts
import { createServer } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  createOhttpGateway,
  createOhttpHandler,
  createStandardEncoding,
} from "@hpke/ohttp";

const { privateKey, publicKey } = await new DhkemX25519HkdfSha256()
  .generateKeyPair();

const gateway = createOhttpGateway({
  keyId: 1,
  kem: new DhkemX25519HkdfSha256(),
  privateKey,
  publicKey,
  kdfAeadPairs: [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }],
  encoding: createStandardEncoding(),
});

const handle = createOhttpHandler({
  gateway,
  forward: async (request) => {
    const response = await fetch(request);
    const headers = new Headers(response.headers);
    headers.delete("content-encoding");
    headers.delete("content-length");
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
});

const server = createServer(async (incoming, outgoing) => {
  try {
    const headers = new Headers();
    for (const [name, value] of Object.entries(incoming.headers)) {
      if (value !== undefined) {
        headers.set(name, Array.isArray(value) ? value.join(", ") : value);
      }
    }

    const request = new Request(
      `http://${incoming.headers.host ?? "localhost"}${incoming.url ?? "/"}`,
      {
        method: incoming.method,
        headers,
        body: incoming.method === "GET" || incoming.method === "HEAD"
          ? undefined
          : Readable.toWeb(incoming) as ReadableStream<Uint8Array>,
        duplex: "half",
      } as RequestInit,
    );
    const url = new URL(request.url);
    let response: Response;
    if (url.pathname === "/ohttp-keys") {
      if (request.method !== "GET") {
        response = new Response(null, {
          status: 405,
          headers: { Allow: "GET" },
        });
      } else {
        const keyConfig = await gateway.publicKeyConfig;
        response = new Response(keyConfig as unknown as BodyInit, {
          headers: { "content-type": "application/ohttp-keys" },
        });
      }
    } else {
      response = await handle(request);
    }

    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    if (response.body) {
      await pipeline(Readable.fromWeb(response.body), outgoing);
    } else {
      outgoing.end();
    }
  } catch (error) {
    console.error(error);
    if (!outgoing.headersSent) outgoing.writeHead(500);
    outgoing.end();
  }
});

server.listen(3000, () => {
  console.log("OHTTP gateway listening on http://localhost:3000");
});
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
