<h1 align="center">@hpke/hybridkem-x-wing</h1>

<div align="center">
<a href="https://jsr.io/@hpke/hybridkem-x-wing"><img src="https://jsr.io/badges/@hpke/hybridkem-x-wing" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for <a href="https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html">X-Wing: general-purpose hybrid post-quantum KEM</a>.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/hybridkem-x-wing/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/hybridkem-x-wing/docs/)

</div>

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

`@hpke/hybridkem-x-wing` need to be used with
[@hpke/core](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md),
which can be installed in the same manner as desribed below.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/hybridkem-x-wing
yarn add @hpke/hybridkem-x-wing
pnpm install @hpke/hybridkem-x-wing
# Using jsr:
npx jsr add @hpke/hybridkem-x-wing
yarn dlx jsr add @hpke/hybridkem-x-wing
pnpm dlx jsr add @@hpke/hybridkem-x-wing
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/hybridkem-x-wing
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
  import { HybridkemXWing } from "https://esm.sh/@hpke/hybridkem-x-wing@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import {
    Aes128Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core";
  import { HybridkemXWing } from "https://esm.sh/@hpke/hybridkem-x-wing";
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
  import { HybridkemXWing } from "https://unpkg.com/@hpke/hybridkem-x-wing@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemXWing(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // Note that the `ct` (ciphertext) resulting from X-Wing Encapsulate() is set to `sender.enc`.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const encrypted = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc, // == `ct` (ciphertext) for X-Wing
  });

  // decrypt
  const pt = await recipient.open(encrypted);

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
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemXWing(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // Note that the `ct` (ciphertext) resulting from X-Wing::Encapsulate() is set to `sender.enc`.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const encrypted = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc, // == `ct` (ciphertext) in the context of X-Wing
  });

  // decrypt
  const pt = await recipient.open(encrypted);

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
      import {
        Aes128Gcm,
        CipherSuite,
        HkdfSha256,
      } from "https://esm.sh/@hpke/core";
      import { HybridkemXWing } from "https://esm.sh/@hpke/hybridkem-x-wing";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new HybridkemXWing(),
            kdf: new HkdfSha256(),
            aead: new Aes128Gcm(),
          });

          const rkp = await suite.kem.generateKeyPair();

          // Note that the `ct` resulting from X-Wing::Encapsulate() is set to `sender.enc`.
          const sender = await suite.createSenderContext({
            recipientPublicKey: rkp.publicKey,
          });
          // encrypt
          const encrypted = await sender.seal(
            new TextEncoder().encode("Hello world!"),
          );

          const recipient = await suite.createRecipientContext({
            recipientKey: rkp.privateKey, // rkp (CryptoKeyPair) is also acceptable.
            enc: sender.enc, // == `ct` (ciphertext) for X-Wing
          });

          // decrypt
          const pt = await recipient.open(encrypted);

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
