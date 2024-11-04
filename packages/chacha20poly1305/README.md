<h1 align="center">@hpke/chacha20poly1305</h1>

<div align="center">
<a href="https://jsr.io/@hpke/chacha20poly1305"><img src="https://jsr.io/badges/@hpke/chacha20poly1305" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for AEAD with ChaCha20-Poly1305, which is implemented by using <a href="https://github.com/paulmillr/noble-ciphers">@noble/ciphers</a></div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/chacha20poly1305/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/chacha20poly1305/docs/)

</div>

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

`@hpke/chacha20poly1305` need to be used with
[@hpke/core](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md),
which can be installed in the same manner as desribed below.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/chacha20poly1305
yarn add @hpke/chacha20poly1305
pnpm install @hpke/chacha20poly1305
# Using jsr:
npx jsr add @hpke/chacha20poly1305
yarn dlx jsr add @hpke/chacha20poly1305
pnpm dlx jsr add @hpke/chacha20poly1305
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/chacha20poly1305
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import {
    CipherSuite,
    DhkemP256HkdfSha256,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core@<SEMVER>";
  import { Chacha20Poly1305 } from "https://esm.sh/@hpke/chacha20poly1305@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import {
    CipherSuite,
    DhkemP256HkdfSha256,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core";
  import { Chacha20Poly1305 } from "https://esm.sh/@hpke/chacha20poly1305";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import {
    CipherSuite,
    DhkemP256HkdfSha256,
    HkdfSha256,
  } from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  import { Chacha20Poly1305 } from "https://unpkg.com/@hpke/chacha20poly1305@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
// const { Chacha20Poly1305 } = require("@hpke/chacha20poly1305");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
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
} catch (err) {
  console.log("failed:", err.message);
}
```

### Deno

```ts
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
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
      // import * as hpke from "https://esm.sh/hpke-js@<SEMVER>";
      import {
        CipherSuite,
        DhkemP256HkdfSha256,
        HkdfSha256,
      } from "https://esm.sh/@hpke/core";
      import { Chacha20Poly1305 } from "https://esm.sh/@hpke/chacha20poly1305";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new DhkemP256HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Chacha20Poly1305(),
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
