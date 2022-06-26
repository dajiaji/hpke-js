<h1 align="center">hpke-js</h1>

<div align="center">
[![Stable Release](https://img.shields.io/npm/v/hpke-js.svg)](https://npm.im/hpke-js)
![Browser CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci_browser.yml/badge.svg)
![Node.js CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci_node.yml/badge.svg)
![Deno CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci.yml/badge.svg)
[![deno doc](https://doc.deno.land/badge.svg)](https://doc.deno.land/https/deno.land/x/hpke/mod.ts)
[![codecov](https://codecov.io/gh/dajiaji/hpke-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2)](https://codecov.io/gh/dajiaji/hpke-js)

</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation build on top of <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>.
This module works on web browsers, Node.js and Deno.
</div>

<p></p>

<div align="center">

[API Documentation](https://doc.deno.land/https://deno.land/x/hpke/mod.ts)

</div>

## Index

- [Supported Features](#supported-features)
- [Supported Environments](#supported-environments)
- [Warnings and Restrictions](#warnings-and-restrictions)
- [Installation](#installation)
  - [Web Browser](#web-browser)
  - [Node.js](#nodejs)
  - [Deno](#deno)
- [Usage](#usage)
  - [Base mode](#base-mode) - for web browsers, Node.js and Deno.
  - [Base mode with Single-Shot APIs](#base-mode-with-single-shot-apis)
  - [Base mode with bidirectional encryption](#base-mode-with-bidirectional-encryption)
  - [Base mode with export-only AEAD](#base-mode-with-export-only-aead)
  - [PSK mode](#psk-mode)
  - [Auth mode](#auth-mode)
  - [AuthPSK mode](#authpsk-mode)
- [Contributing](#contributing)
- [References](#references)

## Supported Features

### HPKE Modes

| Base | PSK | Auth | AuthPSK |
| ---- | --- | ---- | ------- |
| ✅    | ✅   | ✅    | ✅       |

### Key Encapsulation Machanisms (KEMs)

| KEMs                        | Browser | Node.js | Deno |                                                                                                                                                                                                |
| --------------------------- | ------- | ------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DHKEM (P-256, HKDF-SHA256)  | ✅       | ✅       | ✅ v1.23.0-   |                                                                                                                                                                                                |
| DHKEM (P-384, HKDF-SHA384)  | ✅       | ✅       |      |                                                                                                                                                                                                |
| DHKEM (P-521, HKDF-SHA512)  | ✅       | ✅       |      |                                                                                                                                                                                                |
| DHKEM (X25519, HKDF-SHA256) | ✅       | ✅       | ✅   | [@stablelib/x25519](https://www.stablelib.com/modules/_x25519_x25519_.html) is used <br>until [Secure Curves](https://wicg.github.io/webcrypto-secure-curves/) is implemented <br>on browsers. |
| DHKEM (X448, HKDF-SHA512)   | ✅       | ✅       | ✅   | [x448-js](https://github.com/Iskander508/X448-js) is used <br>until [Secure Curves](https://wicg.github.io/webcrypto-secure-curves/) is implemented <br>on browsers.                           |

### Key Derivation Functions (KDFs)

| KDFs        | Browser | Node.js | Deno |   |
| ----------- | ------- | ------- | ---- | - |
| HKDF-SHA256 | ✅       | ✅       | ✅    |   |
| HKDF-SHA384 | ✅       | ✅       | ✅    |   |
| HKDF-SHA512 | ✅       | ✅       | ✅    |   |

### Authenticated Encryption with Associated Data (AEAD) Functions

| AEADs            | Browser | Node.js | Deno |                                                                                                                    |
| ---------------- | ------- | ------- | ---- | ------------------------------------------------------------------------------------------------------------------ |
| AES-128-GCM      | ✅       | ✅       | ✅    |                                                                                                                    |
| AES-256-GCM      | ✅       | ✅       | ✅    |                                                                                                                    |
| ChaCha20Poly1305 | ✅       | ✅       | ✅    | [@stablelib/chacha20poly1305](https://www.stablelib.com/modules/_chacha20poly1305_chacha20poly1305_.html) is used. |
| Export Only      | ✅       | ✅       | ✅    |                                                                                                                    |

## Supported Environments

- **Web Browser**: [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/)
  supported browsers
  - Confirmed: Chrome, Firefox, Edge, Safari, Opera, Vivaldi, Brave
- **Node.js**: 16.x, 17.x, 18.x
- **Deno**: 1.x

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
  import * as hpke from "https://esm.sh/hpke-js@0.12.0";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/hpke-js";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/hpke-js@0.12.0/esm/mod.js";
  // ...
</script>
```

### Node.js

Using npm:

```sh
npm install hpke-js
```

Using yarn:

```sh
yarn add hpke-js
```

### Deno

Using deno.land:

```js
// use a specific version
import * as hpke from "https://deno.land/x/hpke@0.12.0/mod.ts";

// use the latest stable version
import * as hpke from "https://deno.land/x/hpke/mod.ts";
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
      // import * as hpke from "https://esm.sh/hpke-js@0.12.0";
      import { Kem, Kdf, Aead, CipherSuite } from "https://esm.sh/hpke-js@0.12.0";

      globalThis.doHpke = async () => {

        const suite = new CipherSuite({
          kem: Kem.DhkemP256HkdfSha256,
          kdf: Kdf.HkdfSha256,
          aead: Aead.Aes128Gcm
        });
 
        const rkp = await suite.generateKeyPair();
      
        const sender = await suite.createSenderContext({
          recipientPublicKey: rkp.publicKey
        });
      
        const recipient = await suite.createRecipientContext({
          recipientKey: rkp,
          enc: sender.enc,
        });
      
        // encrypt
        const ct = await sender.seal(new TextEncoder().encode("hello world!"));
      
        try {
          // decrypt
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
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
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
import { Kem, Kdf, Aead, CipherSuite } from "https://deno.land/x/hpke@0.12.0/mod.ts";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemX25519HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
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
const { Kem, Kdf, Aead, CipherSuite } = require('hpke-js');

async function doHpke() {

  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm
  });

  const rkp = await suite.generateKeyPair();
  const pt = new TextEncoder().encode('my-secret-message'),

  // encrypt
  const { ct, enc } = await suite.seal({ recipientPublicKey: rkp.publicKey }, pt);

  // decrypt
  try {
  const pt = await suite.open({ recipientKey: rkp, enc: enc }, ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
  } catch (err) {
    console.log("failed to decrypt.");
  }
}

doHpke();
```

### Base mode with bidirectional encryption

Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

const te = new TextEncoder();
const td = new TextDecoder();

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });
  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
  });

  // setup bidirectional encryption
  await sender.setupBidirectional(
    te.encode("seed-for-key"),
    te.encode("seed-for-nonce"),
  );
  await recipient.setupBidirectional(
    te.encode("seed-for-key"),
    te.encode("seed-for-nonce"),
  );

  // encrypt
  const ct = await sender.seal(te.encode("my-secret-message-s"));

  // decrypt
  try {
    const pt = await recipient.open(ct);

    console.log("recipient decrypted: ", td.decode(pt));
    // decrypted: my-secret-message-s
  } catch (err) {
    console.log("failed to decrypt.");
  }

  // encrypt reversely
  const rct = await recipient.seal(te.encode("my-secret-message-r"));

  // decrypt reversely
  try {
    const rpt = await sender.open(rct);

    console.log("sender decrypted: ", td.decode(rpt));
    // decrypted: my-secret-message-r
  } catch (err) {
    console.log("failed to decrypt.");
  }
}

doHpke();
```

### Base mode with export-only AEAD

Node.js:

```js
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.ExportOnly,
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
  });

  const te = new TextEncoder();

  // export
  const pskS = sender.export(te.encode('jugemujugemu'), 32);
  const pskR = recipient.export(te.encode('jugemujugemu'), 32);
  // pskR === pskS
}

doHpke();
```

### PSK mode

Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    },
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
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
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();
  const skp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
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
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();
  const skp = await suite.generateKeyPair();

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
    recipientKey: rkp,
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
