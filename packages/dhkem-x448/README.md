<h1 align="center">@hpke/dhkem-x448</h1>

<div align="center">
<a href="https://jsr.io/@hpke/dhkem-x448"><img src="https://jsr.io/badges/@hpke/dhkem-x448" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for DH-KEM with X448, which is implemented by using <a href="https://github.com/paulmillr/noble-curves">@noble/curves</a></div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/dhkem-x448/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/dhkem-x448/docs/)

</div>

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

`@hpke/dhkem-x448` need to be used with
[@hpke/core](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md),
which can be installed in the same manner as desribed below.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/dhkem-x448
yarn add @hpke/dhkem-x448
pnpm install @hpke/dhkem-x448
# Using jsr:
npx jsr add @hpke/dhkem-x448
yarn dlx jsr add @hpke/dhkem-x448
pnpm dlx jsr add @hpke/dhkem-x448
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/dhkem-x448
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core@<SEMVER>";
  import {
    DhkemX448HkdfSha512,
  } from "https://esm.sh/@hpke/dhkem-x448@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core";
  import * as x448 from "https://esm.sh/@hpke/dhkem-x448";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  import {
    DhkemX448HkdfSha512,
  } from "https://unpkg.com/@hpke/dhkem-x448@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes256Gcm, CipherSuite, HkdfSha512 } from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
// const { DhkemX448HkdfSha512 } = require("@hpke/dhkem-x448");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
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
import { Aes256Gcm, CipherSuite, HkdfSha512 } from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
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
        Aes256Gcm,
        CipherSuite,
        HkdfSha512,
      } from "https://esm.sh/@hpke/core>";
      import { DhkemX448HkdfSha512 } from "https://esm.sh/@hpke/dhkem-x448";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new DhkemX448HkdfSha512(),
            kdf: new HkdfSha512(),
            aead: new Aes256Gcm(),
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
          alert("failed:", err);
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
