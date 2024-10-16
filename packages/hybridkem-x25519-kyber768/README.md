<h1 align="center">@hpke/hybridkem-x25519-kyber768</h1>

<div align="center">
<a href="https://jsr.io/@hpke/hybridkem-x25519-kyber768"><img src="https://jsr.io/badges/@hpke/hybridkem-x25519-kyber768" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for the hybrid post-quantum KEM(X25519, Kyber768) compliant with <a href="https://www.ietf.org/archive/id/draft-westerbaan-cfrg-hpke-xyber768d00-02.html">X25519Kyber768Draft00 hybrid post-quantum KEM for HPKE</a>. The kyber implementation included in this module is based on <a href="https://github.com/antontutoveanu/crystals-kyber-javascript">ntontutoveanu/crystals-kyber-javascript</a> published under <a href="https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/License">the MIT license</a>. Note that this module is EXPERIMENTAL and the referred specification has not been standardized yet.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/hybridkem-x25519-kyber768/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/hybridkem-x25519-kyber768/docs/)

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
npm install @hpke/hybridkem-x25519-kyber768
```

Using yarn:

```sh
yarn add @hpke/hybridkem-x25519-kyber768
```

### Deno

### Deno

Starting from version 1.3.0, hpke-js packages are available from the JSR
registry. From this version onwards, please use JSR import instead of HTTPS
import in Deno.

**JSR imoprt (recommended on `>=1.3.0`):**

Add hpke-js packages using the commands below:

```sh
deno add @hpke/core
deno add @hpke/hybridkem-x25519-kyber768
```

Then, you can use the module from code like this:

```ts
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemX25519Kyber768 } from "@hpke/hybridkem-x25519-kyber768";
```

**HTTPS imoprt (deprecated):**

```ts
import {
  Aes128Gcm,
  CipherSuite,
  HkdfSha256,
} from "https://deno.land/x/hpke/core/mod.ts";
import { HybridkemX25519Kyber768 } from "https://deno.land/x/hpke/x/hybridkem-x25519-kyber768/mod.ts";
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core@<SEMVER>";
  import * as kyber from "https://esm.sh/@hpke/hybridkem-x25519-kyber768@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core";
  import * as kyber from "https://esm.sh/@hpke/hybridkem-x25519-kyber768";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  import * as kyber from "https://unpkg.com/@hpke/hybridkem-x25519-kyber768@<SEMVER>/esm/mod.js";
  // ...
</script>
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/hpke-js.git
cd hpke-js/x/hybridkem-x25519-kyber768
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-hybridkem-x25519-kyber768.js
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemX25519Kyber768 } from "@hpke/hybridkem-x25519-kyber768";
// const { HybridkemX25519Kyber768 } = require("@hpke/hybridkem-x25519-kyber768");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemX25519Kyber768(),
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
import { HybridkemX25519Kyber768 } from "@hpke/hybridkem-x25519-kyber768";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemX25519Kyber768(),
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
      import { HybridkemX25519Kyber768 } from "https://esm.sh/@hpke/hybridkem-x25519-kyber768@<SEMVER>";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new HybridkemX25519Kyber768(),
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
