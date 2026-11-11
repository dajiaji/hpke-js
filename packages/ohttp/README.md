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

Documentation: [jsr.io](https://jsr.io/@hpke/ohttp/doc)

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

The following Node.js example performs an OHTTP request and response roundtrip
without exposing the target request to the relay:

```ts
import { Aes128Gcm, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { OhttpClient, OhttpServer } from "@hpke/ohttp";

async function main() {
  const kem = new DhkemX25519HkdfSha256();
  const kdf = new HkdfSha256();
  const aead = new Aes128Gcm();
  const server = await OhttpServer.setup({
    keyId: 1,
    kem,
    kdfAeadPairs: [{ kdf, aead }],
  });
  const client = new OhttpClient({
    kem,
    kdf,
    aead,
    keyConfig: await server.publicKeyConfig,
    relayUrl: "https://relay.example/ohttp",
  });

  const requestContext = await client.encapsulateRequest(
    new Request("https://target.example/hello", { method: "GET" }),
  );
  const serverContext = await server.decapsulateRequest(
    requestContext.encRequest,
  );
  const encryptedResponse = await serverContext.encapsulateResponse(
    new Response("Hello, OHTTP!"),
  );
  const response = await requestContext.decapsulateResponse(encryptedResponse);

  console.log(await response.text());
}

main().catch((err: unknown) => {
  console.error("OHTTP failed:", err);
});
```

In a deployed client, `OhttpClient.fetch()` sends the encapsulated request to
the configured relay. The gateway uses `OhttpServer.decapsulateRequest()` to
forward the decrypted request to its target and then encapsulates the response.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## License

MIT
