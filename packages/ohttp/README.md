# @hpke/ohttp

Oblivious HTTP client and gateway with explicit cryptographic primitives and
pluggable wire encodings.

## Supported Environments

This package is distributed as ESM only. On Node.js, version 20 or later is
required. Streaming fetch uploads are opt-in and additionally require support
from the runtime, relay, and HTTP connection. The HTTP adapter uses
`duplex: "half"` for streaming uploads; it does not guarantee interactive,
full-duplex exchanges.

## Client

Create a client once, then pass it to `ohttpFetch`. Arguments after the client
have the same shape as `fetch(input, init)` and describe the target request.

This package is distributed as ESM only and requires Node.js 20 or later. It
implements the OHTTP client, gateway and key configuration formats defined by
[RFC 9458](https://www.rfc-editor.org/rfc/rfc9458).

The adapter encodes binary HTTP incrementally, posts the encrypted request to
the relay, validates the response media type, and returns a `Response` with a
decrypted body. It sets the outer Content-Type and Accept headers and, for
chunked encoding, `Incremental: ?1`. Target headers remain inside the encrypted
request. `init.signal` cancels encoding, relay communication, and response
reads. Outer redirects are rejected.

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
  - [Client](#client)
  - [Gateway](#gateway)
  - [Streaming](#streaming)
- [Contributing](#contributing)

Inject the encoding supported by the gateway. There is no automatic fallback or
internal registry.

```ts
import { createStandardEncoding } from "@hpke/ohttp/standard";

const encoding = createStandardEncoding(); // RFC 9458; buffers whole messages
```

```ts
import { createChunkedEncoding } from "@hpke/ohttp/chunked";

const encoding = createChunkedEncoding(); // draft-ietf-ohai-chunked-ohttp-08
```

The base entry point imports neither encoding nor the HTTP adapter. Each
encoding uses only the supplied cryptographic primitives. Applications importing
only the standard encoding exclude chunked framing and authentication logic.
Applications using only low-level binary HTTP streams exclude the HTTP
conversion layer.

| Entry point            | Exports                                                                        |
| ---------------------- | ------------------------------------------------------------------------------ |
| `@hpke/ohttp`          | `createOhttpClient`, `createOhttpGateway`, key configuration helpers and types |
| `@hpke/ohttp/standard` | `createStandardEncoding`                                                       |
| `@hpke/ohttp/chunked`  | `createChunkedEncoding`                                                        |
| `@hpke/ohttp/http`     | `ohttpFetch`, `createOhttpHandler`                                             |

## Streaming requests and responses

Request streams are accepted in both upload modes. By default, the adapter
buffers the encrypted request before sending it, including for chunked encoding.
This supports bodyless GETs and relays reached over HTTP/1.1 without relying on
streaming fetch uploads. Response decryption remains incremental.

To stream relay uploads as well, opt in when creating the client. This requires
streaming-upload support from the runtime and relay; there is no automatic retry
or change of wire encoding:

```ts
const streamingClient = createOhttpClient({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
  keyConfig,
  encoding: createChunkedEncoding(),
  relayUrl: "https://relay.example/ohttp",
  streamingUpload: true,
});

const encoder = new TextEncoder();
const upload = new ReadableStream<Uint8Array>({
  start(controller) {
    controller.enqueue(encoder.encode("first fragment\n"));
    controller.enqueue(encoder.encode("second fragment\n"));
    controller.close();
  },
});

const abort = new AbortController();
const response = await ohttpFetch(
  streamingClient,
  "https://target.example/upload",
  {
    method: "POST",
    body: upload,
    signal: abort.signal,
    // Required by Node.js for streaming Request bodies.
    duplex: "half",
  } as RequestInit,
);

// Process body fragments as they arrive, with backpressure and cancellation.
await response.body!.pipeTo(
  new WritableStream<Uint8Array>({
    write(bytes) {
      // Replace with an incremental parser, file sink, or other destination.
      console.log(bytes);
    },
  }),
);
```

Chunked encoding splits plaintext into chunks of at most 16384 bytes and appends
an authenticated empty final chunk. Receivers limit each plaintext chunk,
including the final chunk, to 16384 bytes by default. Configure a larger bound
with `createChunkedEncoding({ maxChunkSize: 65536 })` only when needed. Declared
lengths over the bound are rejected before reading their payload; final chunks
are bounded while reading. Web Stream fragments, binary HTTP content chunks, and
OHTTP chunks need not align.

Response AEAD authentication failures are reported as OhttpError, with the
original failure retained in cause. For chunked responses this may surface while
reading the body, after the response headers have been returned.

Reading the body to successful completion authenticates finality. Earlier
plaintext can be processed incrementally, but actions requiring a complete
message must wait for successful completion. Truncation or authentication
failure errors the response body and rejects `text()`, `arrayBuffer()`, or
`pipeTo()`. Cancelling a body stops upstream processing without establishing
finality. With standard encoding, messages are buffered before decryption
results become available.

## Gateway

Create the client and gateway with the HPKE primitives you want to use. The
gateway's serialized `keyConfig` is published to clients.

```ts
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { createOhttpGateway } from "@hpke/ohttp";
import { createChunkedEncoding } from "@hpke/ohttp/chunked";
import { createOhttpHandler } from "@hpke/ohttp/http";

const kem = new DhkemX25519HkdfSha256();
const suites = [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }];
const gateway = await createOhttpServer({ keyId: 1, kem, suites });
const client = await createOhttpClient({
  kem,
  suites,
  keyConfig: gateway.keyConfig,
  relayUrl: "https://relay.example/ohttp",
});
```

### Client

`client.fetch()` has the same input shape as `fetch()` and sends the encrypted
request to the configured relay.

```ts
const response = await client.fetch("https://target.example/hello", {
  headers: { "accept": "application/json" },
});
console.log(await response.text());
```

### Gateway

Pass the relay request to `gateway.handle()`. The handler sees the decrypted
target request and returns the response that should be sent back through OHTTP.

```ts
Deno.serve((request) =>
  gateway.handle(request, (targetRequest) => fetch(targetRequest))
);
await decryptedResponse.pipeTo(responseParser);
```

Invalid encapsulated requests receive a 4xx response without invoking the
handler. Errors from the upstream handler are propagated.

### Streaming

The decrypted request and response expose the standard Fetch streaming bodies,
so a gateway can forward a body without buffering it in application code:

```ts
const gatewayResponse = await gateway.handle(
  relayRequest,
  (targetRequest) =>
    fetch(targetRequest.url, {
      method: targetRequest.method,
      headers: targetRequest.headers,
      body: targetRequest.body,
      // Required by Node.js when forwarding a streaming request body.
      duplex: "half",
    } as RequestInit),
);
console.log(gatewayResponse.status);
```

For direct relay integrations, use `client.encapsulateRequest()` and
`gateway.decapsulateRequest()` to exchange `message/ohttp-req` and
`message/ohttp-res` payloads yourself.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## References

- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [RFC 9292: Binary Representation of HTTP Messages](https://www.rfc-editor.org/rfc/rfc9292.html)
- [Chunked Oblivious HTTP Messages, draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.html)
