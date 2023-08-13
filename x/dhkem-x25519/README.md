<h1 align="center">@hpke/dhkem-x25519</h1>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for DH-KEM with X25519, which is implemented by using <a href="https://github.com/paulmillr/noble-curves">@noble/curves</a></div>
<p></p>

<div align="center">

Documentation: [deno.land](https://doc.deno.land/https://deno.land/x/hpke/x/dhkem-x25519/mod.ts) | [pages(only for the latest ver.)](https://dajiaji.github.io/hpke-js/dhkem-x25519/docs/)

</div>

## Index

- [Installation](#installation)
  - [Web Browser](#web-browser)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Cloudflare Workers](#cloudflare-workers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

### Web Browser

Followings are how to use with typical CDNs. Other CDNs can be used as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core@1.1.1";
  import * as x25519 from "https://esm.sh/@hpke/dhkem-x25519@1.1.1";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core";
  import * as x25519 from "https://esm.sh/@hpke/dhkem-x25519";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/@hpke/core@1.1.1/esm/mod.js";
  import * as x25519 from "https://unpkg.com/@hpke/dhkem-x25519@1.1.1/esm/mod.js";
  // ...
</script>
```

### Node.js

Using npm:

```sh
npm install @hpke/dhkem-x25519
```

Using yarn:

```sh
yarn add @hpke/dhkem-x25519
```

### Deno

Using deno.land:

```js
// use a specific version
import * as hpke from "https://deno.land/x/hpke@1.1.1/core/mod.ts";
import * as x25519 from "https://deno.land/x/hpke@1.1.1/x/dhkem-x25519/mod.ts";

// use the latest stable version
import * as hpke from "https://deno.land/x/hpke/core/mod.ts";
import * as x25519 from "https://deno.land/x/hpke/x/dhkem-x25519/mod.ts";
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/hpke-js.git
cd hpke-js/x/dhkem-x25519
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-dhkem-x25519.js
```

## Usage

This section shows some typical usage examples.

### Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import { KdfId, AeadId, CipherSuite } from "https://esm.sh/@hpke/core@1.1.1";
      import { DhkemX25519HkdfSha256 } from "https://esm.sh/@hpke/dhkem-x25519@1.1.1";

      globalThis.doHpke = async () => {

        const suite = new CipherSuite({
          kem: new DhkemX25519HkdfSha256(),
          kdf: KdfId.HkdfSha256,
          aead: AeadId.Aes128Gcm
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

### Node.js

```js
import { KdfId, AeadId, CipherSuite } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
// const { DhkemX25519HkdfSha256 } = require("@hpke/dhkem-x25519");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
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
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  try {
    const pt = await recipient.open(ct);

    console.log("decrypted: ", new TextDecoder().decode(pt));
    // decrypted: my-secret-message
  } catch (err) {
    console.log("failed to decrypt.");
  }
}

doHpke();
```

### Deno

```js
import { KdfId, AeadId, CipherSuite } from "https://deno.land/x/hpke@1.1.1/core/mod.ts";
import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke@1.1.1/x/dhkem-x25519/mod.ts";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
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
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  try {
    // decrypt
    const pt = await recipient.open(ct);

    console.log("decrypted: ", new TextDecoder().decode(pt));
    // decrypted: my-secret-message
  } catch (_err: unknown) {
    console.log("failed to decrypt.");
  }
}

doHpke();
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
