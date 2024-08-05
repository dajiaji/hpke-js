<h1 align="center">@hpke/core</h1>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> core module implemented using only <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>. It does not support the X25519/X448-based KEMs and the ChaCha20Poly1305 AEAD, but it has no external module dependencies. It's small in size and tree-shaking friendly.</div>
<p></p>

<div align="center">

Documentation:
[deno.land](https://doc.deno.land/https://deno.land/x/hpke/core/mod.ts) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/core/docs/)

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
npm install @hpke/core
```

Using yarn:

```sh
yarn add @hpke/core
```

### Deno

Using deno.land:

```js
// use a specific version
import * as hpke from "https://deno.land/x/hpke@1.2.9/core/mod.ts";

// use the latest stable version
import * as hpke from "https://deno.land/x/hpke/core/mod.ts";
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core@1.2.9";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/@hpke/core@1.2.9/esm/mod.js";
  // ...
</script>
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/hpke-js.git
cd hpke-js/core
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-core.js
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
// const {
//   Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256,
// } = require("@hpke/core");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

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

```js
import {
  Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256,
} from "https://deno.land/x/hpke@1.2.9/core/mod.ts";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // decrypt
  const pt = await recipient.open(ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (_err: unknown) {
  console.log("doHPKE() failed.");
}
```

### Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      // import * as hpke from "https://esm.sh/hpke-js@1.2.9";
      import {
        Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256,
      } from "https://esm.sh/@hpke/core@1.2.9";

      globalThis.doHpke = async () => {

        const suite = new CipherSuite({
          kem: new DhkemP256HkdfSha256(),
          kdf: new HkdfSha256(),
          aead: new Aes128Gcm(),
        });
 
        const rkp = await suite.kem.generateKeyPair();
      
        const sender = await suite.createSenderContext({
          recipientPublicKey: rkp.publicKey
        });

        const recipient = await suite.createRecipientContext({
          recipientKey: rkp.privateKey, // rkp (CryptoKeyPair) is also acceptable.
          enc: sender.enc,
        });

        // encrypt
        const ct = await sender.seal(new TextEncoder().encode("hello world!"));
      
        // decrypt
        try {
          const pt = await recipient.open(ct);

          // hello world!
          alert(new TextDecoder().decode(pt));
        } catch (err) {
          alert("failed to decrypt.");
        }
      }
      
    </script>
    <button type="button" onclick="doHpke()">do HPKE</button>
  </body>
</html>
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
