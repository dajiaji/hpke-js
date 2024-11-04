<h1 align="center">@hpke/dhkem-secp256k1</h1>

<div align="center">
<a href="https://jsr.io/@hpke/dhkem-secp256k1"><img src="https://jsr.io/badges/@hpke/dhkem-secp256k1" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for DH-KEM with secp256k1 curve, which is implemented by using <a href="https://github.com/paulmillr/noble-curves">@noble/curves/secp256k1</a>. Note that the extension is EXPERIMENTAL and NOT STANDARDIZED.</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/dhkem-secp256k1/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/dhkem-secp256k1/docs/)

</div>

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

`@hpke/dhkem-secp256k1` need to be used with
[@hpke/core](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md),
which can be installed in the same manner as desribed below.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/dhkem-secp256k1
yarn add @hpke/dhkem-secp256k1
pnpm install @hpke/dhkem-secp256k1
# Using jsr:
npx jsr add @hpke/dhkem-secp256k1
yarn dlx jsr add @hpke/dhkem-secp256k1
pnpm dlx jsr add @hpke/dhkem-secp256k1
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemSecp256k1HkdfSha256 } from "@hpke/dhkem-secp256k1";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/dhkem-secp256k1
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import {
    Aes128Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core@<SEMVER>";
  import {
    DhkemSecp256k1HkdfSha256,
  } from "https://esm.sh/@hpke/dhkem-secp256k1@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import {
    Aes128Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core";
  import {
    DhkemSecp256k1HkdfSha256,
  } from "https://esm.sh/@hpke/dhkem-secp256k1";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import {
    Aes128Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  import {
    DhkemSecp256k1HkdfSha256,
  } from "https://unpkg.com/@hpke/dhkem-secp256k1@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemSecp256k1HkdfSha256 } from "@hpke/dhkem-secp256k1";
// const { DhkemSecp256k1HkdfSha256 } = require("@hpke/dhkem-secp256k1");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemSecp256k1HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
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
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemSecp256k1HkdfSha256 } from "@hpke/dhkem-secp256k1";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemSecp256k1HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
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

### Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import {
        Aes128Gcm,
        CipherSuite,
        HkdfSha256,
      } from "https://esm.sh/@hpke/core";
      import { DhkemSecp256k1HkdfSha256 } from "https://esm.sh/@hpke/dhkem-secp256k1";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new DhkemSecp256k1HkdfSha256(),
            kdf: new HkdfSha256(),
            aead: new Aes128Gcm(),
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
