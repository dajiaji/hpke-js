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
npm install @hpke/ohttp @hpke/core @hpke/dhkem-x25519
```

### Deno

```sh
deno add jsr:@hpke/ohttp jsr:@hpke/core jsr:@hpke/dhkem-x25519
```

### Web Browsers

Load the ESM package from a CDN such as [esm.sh](https://esm.sh/@hpke/ohttp).

## Usage

The standard encoding buffers complete messages. For incremental request and
response processing, use `createChunkedEncoding()` from the main entry point.

```ts
import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import {
  createOhttpClient,
  createOhttpGateway,
  createStandardEncoding,
} from "@hpke/ohttp";

const kem = new DhkemX25519HkdfSha256();
const keyPair = await kem.generateKeyPair();
const encoding = createStandardEncoding();
const gateway = createOhttpGateway({
  keyId: 1,
  kem,
  privateKey: keyPair.privateKey,
  publicKey: keyPair.publicKey,
  kdfAeadPairs: [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }],
  encoding,
});
const client = createOhttpClient({
  kem,
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
  keyConfig: await gateway.publicKeyConfig,
  encoding,
  relayUrl: "https://relay.example/ohttp",
});
```

### Client

`ohttpFetch` mirrors `fetch`: its second argument and `RequestInit` options are
the same as the standard Fetch API.

```ts
import { ohttpFetch } from "@hpke/ohttp";

const response = await ohttpFetch(client, "https://target.example/hello", {
  headers: { accept: "application/json" },
});
console.log(await response.text());
```

### Gateway

Use `createOhttpHandler` with the relay's Fetch request. The callback receives
the decrypted target request.

```ts
import { createOhttpHandler } from "@hpke/ohttp";

const handle = createOhttpHandler({
  gateway,
  forward: (request) => fetch(request),
});

Deno.serve(handle);
```

### Streaming

Chunked encoding supports streaming uploads and incremental response reads when
the runtime and relay support streaming Fetch bodies.

```ts
import { createChunkedEncoding } from "@hpke/ohttp";

const streamingClient = createOhttpClient({
  kem,
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
  keyConfig: await gateway.publicKeyConfig,
  encoding: createChunkedEncoding(),
  relayUrl: "https://relay.example/ohttp",
  streamingUpload: true,
});

const response = await ohttpFetch(
  streamingClient,
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
