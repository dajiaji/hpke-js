<h1 align="center">@hpke/jose</h1>

<div align="center">
<a href="https://www.npmjs.com/package/@hpke/jose"><img src="https://img.shields.io/npm/v/@hpke/jose" alt="npm"/></a>
<a href="https://jsr.io/@hpke/jose"><img src="https://jsr.io/badges/@hpke/jose" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript implementation of <a href="https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/">JOSE-HPKE</a> encryption based on <a href="https://github.com/dajiaji/hpke-js/tree/main/packages/core">@hpke/core</a>.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/jose/doc) |
[Pages](https://dajiaji.github.io/hpke-js/jose/docs/)

</div>

This package is distributed as ESM only and requires Node.js 20 or later. It
implements
[draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-22).

The package provides JWE Integrated Encryption for single recipients and JWE Key
Encryption for multiple recipients. `seal()` produces Compact Serialization for
Integrated Encryption and General JSON Serialization for Key Encryption;
`open()` accepts Compact, Flattened JSON and General JSON Serializations.

PSK mode is supported, with the `psk_id` header parameter carrying
`BASE64URL(id)`. For Key Encryption, the factory selects the HPKE suite used for
key wrapping while its AEAD argument independently selects content encryption.
Content encryption supports `Aes128Gcm` and `Aes256Gcm`; other AEADs are
rejected when constructing the instance.

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Supported Algorithms](#supported-algorithms)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/jose
yarn add @hpke/jose
pnpm install @hpke/jose
# Using jsr:
npx jsr add @hpke/jose
yarn add jsr:@hpke/jose
pnpm add jsr:@hpke/jose
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/jose
```

### Web Browsers

This ESM package can be loaded from a CDN such as
[esm.sh](https://esm.sh/@hpke/jose) or [unpkg](https://unpkg.com/@hpke/jose/).

## Supported Algorithms

| Integrated | Key Encryption | KEM                        | KDF         | AEAD             |
| ---------- | -------------- | -------------------------- | ----------- | ---------------- |
| HPKE-0     | HPKE-0-KE      | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1     | HPKE-1-KE      | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2     | HPKE-2-KE      | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3     | HPKE-3-KE      | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4     | -              | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5     | HPKE-5-KE      | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6     | -              | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7     | HPKE-7-KE      | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |

## Usage

The following Node.js example uses JWE Integrated Encryption. `seal()` returns
the Compact Serialization and `open()` accepts the resulting JWE:

```ts
import { createJoseHpke3 } from "@hpke/jose";

async function main() {
  const jose = createJoseHpke3();
  const recipientKeyPair = await jose.generateKemKeyPair();
  const plaintext = new TextEncoder().encode("Hello, JOSE-HPKE!");

  const jwe = await jose.seal(recipientKeyPair.publicKey, plaintext);
  const decrypted = await jose.open(recipientKeyPair, jwe);

  console.log(new TextDecoder().decode(decrypted));
}

main().catch((err: unknown) => {
  console.error("JOSE-HPKE failed:", err);
});
```

For JWE Key Encryption, use `createJoseHpke3Ke()` with `new Aes128Gcm()` or
`new Aes256Gcm()` as the content-encryption AEAD. The package supports Compact,
Flattened JSON and General JSON Serializations when opening JWE messages.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## License

MIT
