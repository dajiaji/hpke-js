<h1 align="center">@hpke/ohttp</h1>

<div align="center">
<a href="https://www.npmjs.com/package/@hpke/ohttp"><img src="https://img.shields.io/npm/v/@hpke/ohttp" alt="npm"/></a>
<a href="https://jsr.io/@hpke/ohttp"><img src="https://jsr.io/badges/@hpke/ohttp" alt="JSR"/></a>
</div>

<div align="center">
An <a href="https://www.rfc-editor.org/rfc/rfc9458">Oblivious HTTP (OHTTP)</a> client and server implementation using HPKE.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/ohttp/doc) |
[Pages](https://dajiaji.github.io/hpke-js/ohttp/docs/)

</div>

This package is distributed as ESM only and requires Node.js 20 or later. It
implements the OHTTP client, gateway and key configuration formats defined by
RFC 9458.

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
  - [Fetch-like API](#fetch-like-api)
  - [Low-level API](#low-level-api)
- [Contributing](#contributing)

## Installation

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/ohttp @hpke/core @hpke/dhkem-x25519
yarn add @hpke/ohttp @hpke/core @hpke/dhkem-x25519
pnpm install @hpke/ohttp @hpke/core @hpke/dhkem-x25519
# Using jsr:
npx jsr add @hpke/ohttp @hpke/core @hpke/dhkem-x25519
yarn add jsr:@hpke/ohttp jsr:@hpke/core jsr:@hpke/dhkem-x25519
pnpm add jsr:@hpke/ohttp jsr:@hpke/core jsr:@hpke/dhkem-x25519
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/ohttp jsr:@hpke/core jsr:@hpke/dhkem-x25519
```

### Web Browsers

This ESM package can be loaded from a CDN such as
[esm.sh](https://esm.sh/@hpke/ohttp) or [unpkg](https://unpkg.com/@hpke/ohttp/).

## Usage

Both the client and the server (Oblivious Gateway Resource) are created with an
asynchronous factory function that takes the HPKE primitives to use:

```ts
import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { createOhttpClient, createOhttpServer } from "@hpke/ohttp";

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
  relayUrl: "https://relay.example/ohttp",
});
```

### Fetch-like API

`client.fetch()` mirrors the standard `fetch()`: it encapsulates the request,
sends it to the relay and decrypts the response. Its counterpart
`server.handle()` takes the HTTP request forwarded by the relay, passes the
decrypted request to your handler and returns the encapsulated response:

```ts
// Client
const response = await client.fetch("https://target.example/hello");
console.log(await response.text());

// Gateway (e.g. Deno.serve, Cloudflare Workers, Bun.serve)
Deno.serve((request) =>
  server.handle(request, (targetRequest) => fetch(targetRequest))
);
```

`server.handle()` answers requests that cannot be processed with a 4xx response
without calling the handler. Errors thrown by the handler are propagated to the
caller.

### Low-level API

To exchange the encapsulated messages with the relay by yourself, use
`client.encapsulateRequest()` and `server.decapsulateRequest()`. The following
example performs an OHTTP request and response roundtrip without a relay:

```ts
import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { createOhttpClient, createOhttpServer } from "@hpke/ohttp";

async function main() {
  const kem = new DhkemX25519HkdfSha256();
  const suites = [{ kdf: new HkdfSha256(), aead: new Aes128Gcm() }];

  const server = await createOhttpServer({ keyId: 1, kem, suites });
  const client = await createOhttpClient({
    kem,
    suites,
    keyConfig: server.keyConfig,
  });

  // Client: encrypt the request (message/ohttp-req).
  const { encapsulatedRequest, decapsulateResponse } = await client
    .encapsulateRequest(new Request("https://target.example/hello"));

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

main().catch((err: unknown) => {
  console.error("OHTTP failed:", err);
});
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## License

MIT
