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

```ts
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { createOhttpClient } from "@hpke/ohttp";
import { createChunkedEncoding } from "@hpke/ohttp/chunked";
import { ohttpFetch } from "@hpke/ohttp/http";

// Obtain application/ohttp-keys bytes from the gateway's configured key source.
const client = createOhttpClient({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes128Gcm(),
  keyConfig,
  encoding: createChunkedEncoding(),
  relayUrl: "https://relay.example/ohttp",
});

const response = await ohttpFetch(client, "https://target.example/api", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ message: "hello" }),
});
console.log(await response.text());
```

The adapter encodes binary HTTP incrementally, posts the encrypted request to
the relay, validates the response media type, and returns a `Response` with a
decrypted body. It sets the outer Content-Type and Accept headers and, for
chunked encoding, `Incremental: ?1`. Target headers remain inside the encrypted
request. `init.signal` cancels encoding, relay communication, and response
reads. Outer redirects are rejected.

## Choosing an encoding and keeping bundles small

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

`createOhttpGateway` takes an existing key pair. Key generation and rotation
stay under the application's control.

```ts
import { Aes128Gcm, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { createOhttpGateway } from "@hpke/ohttp";
import { createChunkedEncoding } from "@hpke/ohttp/chunked";
import { createOhttpHandler } from "@hpke/ohttp/http";

const kem = new DhkemX25519HkdfSha256();
const keys = await kem.generateKeyPair(); // Generate once, outside the handler.
const gateway = createOhttpGateway({
  keyId: 1,
  kem,
  ...keys,
  kdfAeadPairs: [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }],
  encoding: createChunkedEncoding(),
});

// Serve these bytes from the application's key configuration endpoint.
const keyConfig = await gateway.publicKeyConfig;

const handle = createOhttpHandler({
  gateway,
  async forward(request) {
    // Apply the application's target authorization before forwarding.
    if (new URL(request.url).origin !== "https://target.example") {
      return new Response("Forbidden", { status: 403 });
    }
    const upstream = await fetch(request);
    // fetch decodes content codings but may retain the encoded representation's
    // headers. Forward headers that describe the decoded body.
    const headers = new Headers(upstream.headers);
    headers.delete("content-encoding");
    headers.delete("content-length");
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers,
    });
  },
});

// Pass a relay's POST Request to handle() in your server's request handler.
const response = await handle(incomingRequest);
```

The handler accepts only POSTs with the configured request media type. Malformed
encryption headers, authentication failures, and invalid binary HTTP requests
detected before responding produce 400. Errors discovered later in a streaming
body error that body; an already sent HTTP status cannot be changed. Upstream
and application failures propagate to the hosting server.

When forwarding a native fetch response, use the normalization above: fetch may
decompress the body while retaining Content-Encoding and the compressed
Content-Length. Remove both before returning that decoded body. The handler
cannot infer whether an arbitrary Response body has already been decompressed;
custom forwarders must keep representation headers consistent with their bytes.

Hop-by-hop headers, including fields nominated by Connection, are removed when
encoding HTTP messages. They remain invalid in received binary HTTP. The handler
cancels the upstream body if response encoding fails. The application's
`forward` callback receives a standard `Request` and returns a `Response`. Body
streams are processed incrementally. A forwarder that performs actions requiring
a complete request must consume its body successfully first.

For chunked requests, forwarding can begin before the final chunk is
authenticated. A later truncation can therefore result in 400 after the upstream
has already received part of the request. Returning 400 does not undo upstream
side effects. For operations that require a complete message, validate and
buffer the request body before forwarding, or use standard encoding.

The HTTP adapter emits indeterminate-length binary HTTP and accepts known-length
and indeterminate-length messages. It limits field sections to 64 KiB, consumes
informational responses and trailers without exposing them through Fetch, and
validates trailing padding before reporting body completion.

## Low-level binary HTTP streams

Use the same `encapsulateRequest` / `decapsulateRequest` methods with either
encoding. No dedicated chunked methods or public classes are needed.

```ts
// binaryRequest and binaryResponse contain already encoded binary HTTP bytes.
// Sources may be ReadableStreams, async iterables, or iterables of Uint8Array.
const clientContext = await client.encapsulateRequest(binaryRequest);
const gatewayContext = await gateway.decapsulateRequest(clientContext.body);

// requestParser is a WritableStream connected to an incremental binary HTTP parser.
await gatewayContext.body.pipeTo(requestParser);

const encryptedResponse = await gatewayContext.encapsulateResponse(
  binaryResponse,
);
const decryptedResponse = await clientContext.decapsulateResponse(
  encryptedResponse.body,
);
await decryptedResponse.pipeTo(responseParser);
```

For manual transport, `clientContext.contentType` and
`encryptedResponse.contentType` provide the required media types. All returned
body streams are single-use, and each exchange supports one response. `relayUrl`
is optional when using only low-level APIs. Web Stream cancellation interrupts
pending reads and releases the owned reader. Arbitrary async iterables must
provide their own way to abort an underlying operation; generator return() alone
cannot interrupt a pending next().

## Testing

The package's normal test task and the repository's test:deno task both run the
HTTP/1.1 network regression tests. They can also be run on their own from the
repository root:

```sh
deno test --allow-net packages/ohttp/test/http.integration.ts
```

These exercise both encodings through a local HTTP/1.1 relay and a real upstream
fetch whose responses use Transfer-Encoding: chunked or gzip content coding.

## References

- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html)
- [RFC 9292: Binary Representation of HTTP Messages](https://www.rfc-editor.org/rfc/rfc9292.html)
- [Chunked Oblivious HTTP Messages, draft-ietf-ohai-chunked-ohttp-08](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-08.html)
