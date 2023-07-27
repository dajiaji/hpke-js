<h1 align="center">@hpke/dhkem-secp256k1</h1>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for DH-KEM with secp256k1 curve, which is implemented by using <a href="https://github.com/paulmillr/noble-curves">@noble/curves/secp256k1</a>. Note that the extension is EXPERIMENTAL and NOT STANDARDIZED.</div>
<p></p>

<div align="center">

[Documentation](https://doc.deno.land/https://deno.land/x/hpke/x/dhkem-secp256k1/mod.ts)

</div>

## Index

- [Supported Environments](#supported-environments)
- [Installation](#installation)
  - [Web Browser](#web-browser)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Cloudflare Workers](#cloudflare-workers)
- [Usage](#usage)
- [Contributing](#contributing)

## Supported Environments

- **Web Browser**: [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
  supported browsers
  - Confirmed: Chrome, Firefox, Edge, Safari, Opera, Vivaldi, Brave
- **Node.js**: 16.x, 17.x, 18.x, 19.x, 20.x
- **Deno**: 1.x (1.15-)
- **Cloudflare Workers**
- **bun**: 0.x (0.3.0-)

## Installation

### Web Browser

Followings are how to use with typical CDNs. Other CDNs can be used as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/hpke-js@0.22.2";
  import * as secp256k1 from "https://esm.sh/@hpke/dhkem-secp256k1@0.22.2";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/hpke-js";
  import * as secp256k1 from "https://esm.sh/@hpke/dhkem-secp256k1";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/hpke-js@0.22.2/esm/mod.js";
  import * as secp256k1 from "https://unpkg.com/@hpke/dhkem-secp256k1@0.22.2/esm/mod.js";
  // ...
</script>
```

### Node.js

Using npm:

```sh
npm install @hpke/dhkem-secp256k1
```

Using yarn:

```sh
yarn add @hpke/dhkem-secp256k1
```

### Deno

Using deno.land:

```js
// use a specific version
import * as hpke from "https://deno.land/x/hpke@0.22.2/mod.ts";
import * as secp256k1 from "https://deno.land/x/hpke@0.22.2/x/dhkem-secp256k1/mod.ts";

// use the latest stable version
import * as hpke from "https://deno.land/x/hpke/mod.ts";
import * as secp256k1 from "https://deno.land/x/hpke/x/dhkem-secp256k1/mod.ts";
```

### Cloudflare Workers

Downloads a single js file from esm.sh:

```sh
curl -sS -o $YOUR_SRC_PATH/hpke.min.js https://esm.sh/v86/hpke-js@0.22.2/es2022/hpke.min.js
curl -sS -o $YOUR_SRC_PATH/hpke-dhkem-secp256k1.min.js https://esm.sh/v86/@hpke/dhkem-secp256k1@0.22.2/es2022/hpke-dhkem-secp256k1.min.js
```

## Usage

This section shows some typical usage examples.

### Base mode

Browsers:

```html
<html>
  <head></head>
  <body>
    <script type="module">
      // import * as hpke from "https://esm.sh/hpke-js@0.22.2";
      import { KemId, KdfId, AeadId, CipherSuite } from "https://esm.sh/hpke-js@0.22.2";
      import { DhkemSecp256k1HkdfSha256 } from "https://esm.sh/@hpke/dhkem-secp256k1@0.22.2";

      globalThis.doHpke = async () => {

        const suite = new CipherSuite({
          kem: new DhkemSecp256k1HkdfSha256(),
          kdf: KdfId.HkdfSha256,
          aead: AeadId.Aes128Gcm
        });
 
        const rkp = await suite.generateKeyPair();
      
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

Node.js:

```js
const { KemId, KdfId, AeadId, CipherSuite } = require("hpke-js");
const { DhkemSecp256k1HkdfSha256 } = require("@hpke/dhkem-secp256k1");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemSecp256k1HkdfSha256(),
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

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

Deno:

```js
import { KemId, KdfId, AeadId, CipherSuite } from "https://deno.land/x/hpke@0.22.2/mod.ts";
import { DhkemSecp256k1HkdfSha256 } from "https://deno.land/x/hpke@0.22.2/x/dhkem-secp256k1/mod.ts";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemSecp256k1HkdfSha256(),
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

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
