<h1 align="center">hpke-js</h1>

<div align="center">
<a href="https://jsr.io/@hpke/hpke-js"><img src="https://jsr.io/badges/@hpke/hpke-js" alt="JSR"/></a>
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_browser.yml/badge.svg" alt="Browser CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_node.yml/badge.svg" alt="Node.js CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci.yml/badge.svg" alt="Deno CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_cloudflare.yml/badge.svg" alt="Cloudflare Workers CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_bun.yml/badge.svg" alt="bun CI" />
<a href="https://codecov.io/gh/dajiaji/hpke-js">
  <img src="https://codecov.io/gh/dajiaji/hpke-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2" alt="codecov" />
</a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation build on top of <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>.
This module works on web browsers, Node.js, Deno and various other JavaScript runtimes.
</div>

<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/hpke-js/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/docs/)

</div>

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

Where possible, it is recommended to use `@hpke/core` along with extension
modules (such as `@hpke/chacha20poly1305`) instead of `hpke-js`.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install hpke-js
yarn add hpke-js
pnpm install hpke-js
# Using jsr:
npx jsr add hpke-js
yarn dlx jsr add hpke-js
pnpm dlx jsr add hpke-js
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/hpke-js
```

### Web Browsers

Followings are how to use the module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import {
    AeadId,
    CipherSuite,
    KdfId,
    KemId,
  } from "https://esm.sh/hpke-js@<SEMVER>";
  // import * as hpke from "https://esm.sh/@hpke/core@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import { AeadId, CipherSuite, KdfId, KemId } from "https://esm.sh/hpke-js";
  // import * as hpke from "https://esm.sh/@hpke/core";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import {
    AeadId,
    CipherSuite,
    KdfId,
    KemId,
  } from "https://unpkg.com/hpke-js@<SEMVER>/esm/mod.js";
  // import * as hpke from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305,
  });

  // A recipient generates a key pair.
  const rkp = await suite.kem.generateKeyPair();

  // A sender encrypts a message with the recipient public key.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // The recipient decrypts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });
  const pt = await recipient.open(ct);

  // Hello world!
  console.log("decrypted: ", new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (e) {
  console.log("failed:", e.message);
}
```

### Deno

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305,
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });

  // decrypt
  const pt = await recipient.open(ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (_err: unknown) {
  console.log("failed.");
}
```

### Web Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import { AeadId, CipherSuite, KdfId, KemId } from "https://esm.sh/hpke-js";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: KemId.DhkemP256HkdfSha256,
            kdf: KdfId.HkdfSha256,
            aead: AeadId.Aes128Gcm,
          });

          const rkp = await suite.kem.generateKeyPair();

          const sender = await suite.createSenderContext({
            recipientPublicKey: rkp.publicKey,
          });

          // encrypt
          const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

          const recipient = await suite.createRecipientContext({
            recipientKey: rkp.privateKey, // rkp (CryptoKeyPair) is also acceptable.
            enc: sender.enc,
          });

          // decrypt
          const pt = await recipient.open(ct);

          // Hello world!
          alert(new TextDecoder().decode(pt));
        } catch (err) {
          alert("failed:", err.message);
        }
      };
    </script>
    <button type="button" onclick="doHpke()">do HPKE</button>
  </body>
</html>
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
