<h1 align="center">hpke-js</h1>

<div align="center">

[![deno doc](https://doc.deno.land/badge.svg)](https://doc.deno.land/https/deno.land/x/hpke/mod.ts)
![Browser CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci_browser.yml/badge.svg)
![Node.js CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci_node.yml/badge.svg)
![Deno CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci.yml/badge.svg)
![Cloudflare Workers CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci_cloudflare.yml/badge.svg)
![bun CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci_bun.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/hpke-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2)](https://codecov.io/gh/dajiaji/hpke-js)

</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation build on top of <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>.
This module works on web browsers, Node.js, Deno and various other JavaScript runtimes.
</div>

<p></p>

<div align="center">

Documentation:
[deno.land](https://doc.deno.land/https://deno.land/x/hpke/mod.ts) |
[pages(only for the latest ver.)](https://dajiaji.github.io/hpke-js/docs/)

</div>

For Node.js, you can install `hpke-js` via npm/yarn:

```sh
npm install @hpke/core
# if necessary...
npm install @hpke/dhkem-x25519
npm install @hpke/dhkem-x448
npm install @hpke/chacha20poly1305
# ...or you can use the v0.x-compatible all-in-one package below.
npm install hpke-js
```

Then, you can use it as follows:

```js
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  // A recipient generates a key pair.
  const rkp = await suite.kem.generateKeyPair();

  // A sender encrypts a message with the recipient public key.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // The recipient decrypts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });
  try {
    const pt = await recipient.open(ct);
    console.log("decrypted: ", new TextDecoder().decode(pt));
  } catch (e) {
    console.log("failed to decrypt:", e.message);
  }
}

doHpke();
```

## Index

- [Packages](#packages)
- [Supported Features](#supported-features)
- [Supported Environments](#supported-environments)
- [Warnings and Restrictions](#warnings-and-restrictions)
- [Installation](#installation)
  - [Web Browser](#web-browser)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Cloudflare Workers](#cloudflare-workers)
- [Usage](#usage)
  - [Base mode](#base-mode) - for web browsers, Node.js and Deno.
  - [Base mode with Single-Shot APIs](#base-mode-with-single-shot-apis)
  - [Base mode with export-only AEAD](#base-mode-with-export-only-aead)
  - [PSK mode](#psk-mode)
  - [Auth mode](#auth-mode)
  - [AuthPSK mode](#authpsk-mode)
- [Contributing](#contributing)
- [References](#references)

## Packages

The hpke-js includes the following packages.

| name                   | since   | description                                                                                                                                                                                                                                                                                                                               |
| ---------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| hpke-js                | v0.1.0- | The HPKE module supporting all of the ciphersuites defined in [RFC9180](https://datatracker.ietf.org/doc/html/rfc9180), which consists of the following @hpke/{core, dhkem-x25519, dhkem-x448, chacha20poly1305} internally.                                                                                                              |
| @hpke/core             | v1.0.0- | The HPKE core module implemented using only [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/). It does not support the X25519/X448-based KEMs and the ChaCha20/Poly1305 AEAD, but it has no external module dependencies and is small in size. See [/core/README](https://github.com/dajiaji/hpke-js/blob/main/core/README.md). |
| @hpke/dhkem-x25519     | v1.0.0- | The HPKE extension module for DHKEM(X25519, HKDF-SHA256). See [/x/dhkem-x25519/README](https://github.com/dajiaji/hpke-js/blob/main/x/dhkem-x25519/README.md).                                                                                                                                                                            |
| @hpke/dhkem-x448       | v1.0.0- | The HPKE extension module for DHKEM(X448, HKDF-SHA512). See [/x/dhkem-x448/README](https://github.com/dajiaji/hpke-js/blob/main/x/dhkem-x448/README.md).                                                                                                                                                                                  |
| @hpke/chacha20poly1305 | v1.0.0- | The HPKE extension module for ChaCha20Poly1305 AEAD. See [/x/chacha20poly1305/README](https://github.com/dajiaji/hpke-js/blob/main/x/chacha20poly1305/README.md).                                                                                                                                                                         |
| @hpke/dhkem-secp256k1  | v1.0.0- | [EXPERIMENTAL AND NOT STANDARDIZED] The HPKE extension module for DHKEM(secp256k1, HKDF-SHA256). See [/x/dhkem-secp256k1/README](https://github.com/dajiaji/hpke-js/blob/main/x/dhkem-secp256k1/README.md).                                                                                                                               |

## Supported Features

### HPKE Modes

| Base | PSK | Auth | AuthPSK |
| ---- | --- | ---- | ------- |
| ✅   | ✅  | ✅   | ✅      |

### Key Encapsulation Machanisms (KEMs)

| KEMs                           | Browser                             | Node.js                             | Deno                                | Cloudflare<br>Workers               | bun                                 |
| ------------------------------ | ----------------------------------- | ----------------------------------- | ----------------------------------- | ----------------------------------- | ----------------------------------- |
| DHKEM (P-256, HKDF-SHA256)     | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         |
| DHKEM (P-384, HKDF-SHA384)     | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         |
| DHKEM (P-521, HKDF-SHA512)     | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         |                                     | ✅<br>hpke-js<br>@hpke/core         | ✅<br>hpke-js<br>@hpke/core         |
| DHKEM (X25519, HKDF-SHA256)    | ✅<br>hpke-js<br>@hpke/dhkem-x25519 | ✅<br>hpke-js<br>@hpke/dhkem-x25519 | ✅<br>hpke-js<br>@hpke/dhkem-x25519 | ✅<br>hpke-js<br>@hpke/dhkem-x25519 | ✅<br>hpke-js<br>@hpke/dhkem-x25519 |
| DHKEM (X448, HKDF-SHA512)      | ✅<br>hpke-js<br>@hpke/dhkem-x448   | ✅<br>hpke-js<br>@hpke/dhkem-x448   | ✅<br>hpke-js<br>@hpke/dhkem-x448   | ✅<br>hpke-js<br>@hpke/dhkem-x448   | ✅<br>hpke-js<br>@hpke/dhkem-x448   |
| DHKEM (secp256k1, HKDF-SHA256) | ✅<br>@hpke/dhkem-secp256k1         | ✅<br>@hpke/dhkem-secp256k1         | ✅<br>@hpke/dhkem-secp256k1         | ✅<br>@hpke/dhkem-secp256k1         | ✅<br>@hpke/dhkem-secp256k1         |

### Key Derivation Functions (KDFs)

| KDFs        | Browser                          | Node.js                          | Deno                             | Cloudflare<br>Workers            | bun                              |
| ----------- | -------------------------------- | -------------------------------- | -------------------------------- | -------------------------------- | -------------------------------- |
| HKDF-SHA256 | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) |
| HKDF-SHA384 | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) |
| HKDF-SHA512 | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) | ✅<br>hpke-js<br>@hpke/core(\*1) |

- (\*1) The HKDF functions built in `@hpke/core` can derive keys of the same
  length as the hash size. If you want to derive keys longer than the hash size,
  use `hpke-js`.

### Authenticated Encryption with Associated Data (AEAD) Functions

| AEADs                | Browser                                     | Node.js                                     | Deno                                        | Cloudflare<br>Workers                       | bun                                         |
| -------------------- | ------------------------------------------- | ------------------------------------------- | ------------------------------------------- | ------------------------------------------- | ------------------------------------------- |
| AES-128-GCM          | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 |
| AES-256-GCM          | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 |
| ChaCha20<br>Poly1305 | ✅<br>hpke-js<br>@hpke/chacha<br>20poly1305 | ✅<br>hpke-js<br>@hpke/chacha<br>20poly1305 | ✅<br>hpke-js<br>@hpke/chacha<br>20poly1305 | ✅<br>hpke-js<br>@hpke/chacha<br>20poly1305 | ✅<br>hpke-js<br>@hpke/chacha<br>20poly1305 |
| Export Only          | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 | ✅<br>hpke-js<br>@hpke/core                 |

## Supported Environments

- **Web Browser**: [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
  supported browsers
  - Confirmed: Chrome, Firefox, Edge, Safari, Opera, Vivaldi, Brave
- **Node.js**: 16.x, 17.x, 18.x, 19.x, 20.x
- **Deno**: 1.x (1.25-)
- **Cloudflare Workers**
- **bun**: 0.x (0.4.0-)

## Warnings and Restrictions

- Although this library has been passed the following test vectors, it has not
  been formally audited.
  - [RFC9180 official test vectors provided on github.com/cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json)
  - [ECDH/X25519/X448 test vectors provided on Project Wycheproof](https://github.com/google/wycheproof)
- The upper limit of the AEAD sequence number is further rounded to JavaScript's
  MAX\_SAFE\_INTEGER (`2^53-1`).

## Installation

### Web Browser

Followings are how to use with typical CDNs. Other CDNs can be used as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core@1.1.1";
  // import * as hpke from "https://esm.sh/hpke-js@1.1.1";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/@hpke/core";
  // import * as hpke from "https://esm.sh/hpke-js";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/@hpke/core@1.1.1/esm/mod.js";
  // import * as hpke from "https://unpkg.com/hpke-js@1.1.1/esm/mod.js";
  // ...
</script>
```

### Node.js

Using npm:

```sh
npm install @hpke/core
# if necessary...
npm install @hpke/dhkem-x25519
npm install @hpke/dhkem-x448
npm install @hpke/chacha20poly1305
# ...or you can use the v0.x-compatible all-in-one package below.
npm install hpke-js
```

Using yarn:

```sh
yarn add @hpke/core
# if necessary...
yarn add @hpke/dhkem-x25519
yarn add @hpke/dhkem-x448
yarn add @hpke/chacha20poly1305
# ...or you can use the v0.x-compatible all-in-one package below.
yarn add hpke-js
```

### Deno

Using deno.land:

```js
// use a specific version
import * as hpke from "https://deno.land/x/hpke@1.1.1/core/mod.ts";
// import * as hpke from "https://deno.land/x/hpke@1.1.1/x/dhkem-x25519/mod.ts";
// import * as hpke from "https://deno.land/x/hpke@1.1.1/mod.ts";

// use the latest stable version
import * as hpke from "https://deno.land/x/hpke/core/mod.ts";
// import * as hpke from "https://deno.land/x/hpke/x/dhkem-x25519/mod.ts";
// import * as hpke from "https://deno.land/x/hpke/mod.ts";
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/hpke-js.git
cd hpke-js
# for hpke-js
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke.js

# for @hpke/core
cd hpke-js/core
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-core.js

# for @hpke/dhkem-x25519
cd hpke-js/x/dhkem-x25519
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/hpke-dhkem-x25519.js
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
      import { KemId, KdfId, AeadId, CipherSuite } from "https://esm.sh/@hpke/core@1.1.1";
      // import { KemId, KdfId, AeadId, CipherSuite } from "https://esm.sh/hpke-js@1.1.1";

      globalThis.doHpke = async () => {

        const suite = new CipherSuite({
          kem: KemId.DhkemP256HkdfSha256,
          kdf: KdfId.HkdfSha256,
          aead: AeadId.Aes128Gcm
        });
 
        const rkp = await suite.kem.generateKeyPair();
      
        const sender = await suite.createSenderContext({
          recipientPublicKey: rkp.publicKey
        });
      
        // A JWK-formatted recipient public key can also be used.
        // const jwkPkR = {
        //   kty: "EC",
        //   crv: "P-256",
        //   kid: "P-256-01",
        //   x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
        //   y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
        //   key_ops: [],
        // };
        // const pkR = await suite.kem.importKey("jwk", jwkPkR, true);
        // const sender = await suite.createSenderContext({
        //   recipientPublicKey: pkR,
        // });

        const recipient = await suite.createRecipientContext({
          recipientKey: rkp.privateKey, // rkp (CryptoKeyPair) is also acceptable.
          enc: sender.enc,
        });

        // A JWK-formatted recipient private key can also be used.
        // const jwkSkR = {
        //   kty: "EC",
        //   crv: "P-256",
        //   kid: "P-256-01",
        //   x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
        //   y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
        //   d: "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
        //   key_ops: ["deriveBits"],
        // };
        // const skR = await suite.kem.importKey("jwk", jwkSkR, false);
        // const recipient = await suite.createRecipientContext({
        //   recipientKey: skR,
        //   enc: sender.enc,
        // });

      
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
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  // A recipient generates a key pair.
  const rkp = await suite.kem.generateKeyPair();

  // A sender encrypts a message with the recipient public key.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // The recipient decrypts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });
  try {
    const pt = await recipient.open(ct);
    console.log("decrypted: ", new TextDecoder().decode(pt));
  } catch (e) {
    console.log("failed to decrypt:", e.message);
  }
}

doHpke();
```

Deno:

```js
import { KemId, KdfId, AeadId, CipherSuite } from "https://deno.land/x/hpke@1.1.1/core/mod.ts";
import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke@1.1.1/x/dhkem-x25519/mod.ts";
// import { KemId, KdfId, AeadId, CipherSuite } from "https://deno.land/x/hpke@1.1.1/mod.ts";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    // If you use "https://deno.land/x/hpke@1.1.1/mod.ts", you can specify it with id as follows:
    // kem: KemId.DhkemX25519HkdfSha256, 
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

### Base mode with Single-Shot APIs

Node.js:

```js
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {

  // setup
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm
  });

  const rkp = await suite.kem.generateKeyPair();
  const pt = new TextEncoder().encode('my-secret-message'),

  // encrypt
  const { ct, enc } = await suite.seal({ recipientPublicKey: rkp.publicKey }, pt);

  // decrypt
  try {
  const pt = await suite.open({ recipientKey: rkp.privateKey, enc: enc }, ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
  } catch (err) {
    console.log("failed to decrypt.");
  }
}

doHpke();
```

### Base mode with export-only AEAD

Node.js:

```js
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.ExportOnly,
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });

  const te = new TextEncoder();

  // export
  const pskS = sender.export(te.encode("jugemujugemu"), 32);
  const pskR = recipient.export(te.encode("jugemujugemu"), 32);
  // pskR === pskS
}

doHpke();
```

### PSK mode

Node.js:

```js
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    },
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    },
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  try {
    const pt = await recipient.open(ct);

    console.log("decrypted: ", new TextDecoder().decode(pt));
    // decrypted: my-secret-message
  } catch (err) {
    console.log("failed to decrypt:", err.message);
  }
}

doHpke();
```

### Auth mode

Node.js:

```js
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.kem.generateKeyPair();
  const skp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
    senderPublicKey: skp.publicKey,
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  try {
    // decrypt
    const pt = await recipient.open(ct);

    console.log("decrypted: ", new TextDecoder().decode(pt));
    // decrypted: my-secret-message
  } catch (err) {
    console.log("failed to decrypt:", err.message);
  }
}

doHpke();
```

### AuthPSK mode

Node.js:

```js
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.kem.generateKeyPair();
  const skp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    },
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
    senderPublicKey: skp.publicKey,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    },
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  try {
    const pt = await recipient.open(ct);

    console.log("decrypted: ", new TextDecoder().decode(pt));
    // decrypted: my-secret-message
  } catch (err) {
    console.log("failed to decrypt:", err.message);
  }
}

doHpke();
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## References

- [RFC9180: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/rfc9180)
- [W3C/WICG: Secure Curves in the Web Cryptography API](https://wicg.github.io/webcrypto-secure-curves/)
