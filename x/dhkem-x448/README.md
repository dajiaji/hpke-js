<h1 align="center">@hpke/dhkem-x448</h1>

<!--
<div align="center">
<a href="https://jsr.io/@hpke/dhkem-x448"><img src="https://jsr.io/badges/@hpke/dhkem-x448" alt="JSR"/></a>
</div>
-->

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for DH-KEM with X448, which is implemented by using <a href="https://github.com/paulmillr/noble-curves">@noble/curves</a></div>
<p></p>

<div align="center">

Documentation:
[deno.land](https://doc.deno.land/https://deno.land/x/hpke/x/dhkem-x448/mod.ts)
|
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/dhkem-x448/docs/)

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
npm install @hpke/dhkem-x448
```

Using yarn:

```sh
yarn add @hpke/dhkem-x448
```

### Deno

Using deno.land:

```js
// use a specific version
import * as hpke from "https://deno.land/x/hpke@1.2.9/core/mod.ts";
import * as x448 from "https://deno.land/x/hpke@1.2.9/x/dhkem-x448/mod.ts";

// use the latest stable version
import * as hpke from "https://deno.land/x/hpke/core/mod.ts";
import * as x448 from "https://deno.land/x/hpke/x/dhkem-x448/mod.ts";
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core@1.2.9";
  import * as x448 from "https://esm.sh/@hpke/dhkem-x448@1.2.9";
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
  import * as hpke from "https://unpkg.com/@hpke/core@1.2.9/esm/mod.js";
  import * as x448 from "https://unpkg.com/@hpke/dhkem-x448@1.2.9/esm/mod.js";
  // ...
</script>
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/hpke-js.git
cd hpke-js/x/dhkem-x448
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-dhkem-x448.js
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

```js
import { KdfId, AeadId, CipherSuite } from "https://deno.land/x/hpke@1.2.9/core/mod.ts";
import { DhkemX448HkdfSha512 } from "https://deno.land/x/hpke@1.2.9/x/dhkem-x448/mod.ts";

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
      import { Aes256Gcm, CipherSuite, HkdfSha512 } from "https://esm.sh/@hpke/core@1.2.9";
      import { DhkemX448HkdfSha512 } from "https://esm.sh/@hpke/dhkem-x448@1.2.9";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new DhkemX448HkdfSha512(),
            kdf: new HkdfSha512(),
            aead: new Aes256Gcm(),
          });
 
          const rkp = await suite.kem.generateKeyPair();
      
          const sender = await suite.createSenderContext({
            recipientPublicKey: rkp.publicKey
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
      }
    </script>
    <button type="button" onclick="doHpke()">do HPKE</button>
  </body>
</html>
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
