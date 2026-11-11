<h1 align="center">@hpke/cose</h1>

<div align="center">
<a href="https://www.npmjs.com/package/@hpke/cose"><img src="https://img.shields.io/npm/v/@hpke/cose" alt="npm"/></a>
<a href="https://jsr.io/@hpke/cose"><img src="https://jsr.io/badges/@hpke/cose" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript implementation of <a href="https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/">COSE-HPKE</a> built on top of <a href="https://github.com/dajiaji/hpke-js/tree/main/packages/core">@hpke/core</a>.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/cose/doc)

</div>

This package is tested against the test vectors in
[draft-ietf-cose-hpke-27](https://datatracker.ietf.org/doc/html/draft-ietf-cose-hpke-27).
It is distributed as ESM only and requires Node.js 20 or later.

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
npm install @hpke/cose
yarn add @hpke/cose
pnpm install @hpke/cose
# Using jsr:
npx jsr add @hpke/cose
yarn add jsr:@hpke/cose
pnpm add jsr:@hpke/cose
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/cose
```

### Web Browsers

This ESM package can be loaded from a CDN such as
[esm.sh](https://esm.sh/@hpke/cose) or [unpkg](https://unpkg.com/@hpke/cose/).

## Supported Algorithms

| Name   | COSE Value | KEM                        | KDF         | AEAD             |
| ------ | ---------- | -------------------------- | ----------- | ---------------- |
| HPKE-0 | 35         | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1 | 37         | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2 | 39         | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3 | 41         | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4 | 42         | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5 | 43         | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6 | 44         | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7 | 45         | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |

Key Encryption variants (HPKE-0-KE through HPKE-7-KE) use COSE values 46–53.

## Usage

The following Node.js example uses COSE_Encrypt0 (integrated encryption) with
DHKEM(X25519), HKDF-SHA256 and AES-128-GCM:

```ts
import { createCoseHpke3 } from "@hpke/cose";

async function main() {
  const cose = createCoseHpke3();
  const recipientKeyPair = await cose.generateKemKeyPair();
  const plaintext = new TextEncoder().encode("Hello, COSE-HPKE!");

  const ciphertext = await cose.seal(
    recipientKeyPair.publicKey,
    plaintext,
  );
  const decrypted = await cose.open(recipientKeyPair, ciphertext);

  console.log(new TextDecoder().decode(decrypted));
}

main().catch((err: unknown) => {
  console.error("COSE-HPKE failed:", err);
});
```

For COSE_Encrypt (key encryption), use `createCoseHpke3Ke()` and pass a
content-encryption AEAD such as `new Aes128Gcm()` to the factory. The package
supports HPKE-0 through HPKE-7 and their key-encryption variants.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## License

MIT
