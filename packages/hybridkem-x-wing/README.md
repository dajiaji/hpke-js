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
  - [Cloudflare Workers](#cloudflare-workers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

### Node.js

Using npm:

```sh
npm install @hpke/hybridkem-x-wing
```

Using yarn:

```sh
yarn add @hpke/hybridkem-x-wing
```

### Deno

Starting from version 1.3.0, hpke-js packages are available from the JSR
registry. From this version onwards, please use JSR import instead of HTTPS
import in Deno.

**JSR imoprt (recommended on `>=1.3.0`):**

Add hpke-js packages using the commands below:

```sh
deno add @hpke/core
deno add @hpke/hybridkem-x-wing
```

Then, you can use the module from code like this:

```ts
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";
```

**HTTPS imoprt (deprecated):**

```ts
import {
  Aes128Gcm,
  CipherSuite,
  HkdfSha256,
} from "https://deno.land/x/hpke/core/mod.ts";
import { HybridkemXWing } from "https://deno.land/x/hpke/x/hybridkem-x-wing/mod.ts";
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core@<SEMVER>";
  import * as kyber from "https://esm.sh/@hpke/hybridkem-x-wing@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core";
  import * as kyber from "https://esm.sh/@hpke/hybridkem-x-wing";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  import * as kyber from "https://unpkg.com/@hpke/hybridkem-x-wing@<SEMVER>/esm/mod.js";
  // ...
</script>
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/hpke-js.git
cd hpke-js/x/hybridkem-x-wing
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-hybridkem-x-wing.js
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";
// const { HybridkemXWing } = require("@hpke/hybridkem-x-wing");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemXWing(),
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
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemXWing(),
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
      } from "https://esm.sh/@hpke/core@<SEMVER>";
      import { HybridkemXWing } from "https://esm.sh/@hpke/hybridkem-x-wing@<SEMVER>";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new HybridkemXWing(),
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
