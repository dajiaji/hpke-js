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
[RFC 9458](https://www.rfc-editor.org/rfc/rfc9458).

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

Create the client and gateway with the HPKE primitives you want to use. The
gateway's serialized `keyConfig` is published to clients.

```ts
import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { createOhttpClient, createOhttpServer } from "@hpke/ohttp";

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

## License

MIT
