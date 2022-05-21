<h1 align="center">hpke-js</h1>

<div align="center">

[![Stable Release](https://img.shields.io/npm/v/hpke-js.svg)](https://npm.im/hpke-js)
![Github CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/hpke-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2)](https://codecov.io/gh/dajiaji/hpke-js)

</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation build on top of <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>.
This library works on both web browsers and Node.js (<b>currently, Deno is not supported</b>).
</div>

<p></p>

<div align="center">

[API Documentation](https://dajiaji.github.io/hpke-js/)

</div>

## Index

- [Supported Features](#supported-features)
- [Installation](#installation)
- [Usage](#usage)
  - [Base mode](#base-mode)
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
| ✅   | ✅  | ✅   | ✅      |

### Key Encapsulation Machanisms (KEMs)

| KEMs                        | Browser | Node.js | Deno |
| --------------------------- | ------- | ------- | ---- |
| DHKEM (P-256, HKDF-SHA256)  | ✅      |  ✅     |      |
| DHKEM (P-384, HKDF-SHA384)  | ✅      |  ✅     |      |
| DHKEM (P-521, HKDF-SHA512)  | ✅      |  ✅     |      |
| DHKEM (X25519, HKDF-SHA256) | ✅      |  ✅     |      |
| DHKEM (X448, HKDF-SHA512)   |         |         |      |

### Key Derivation Functions (KDFs)

| KDFs        | Browser | Node.js | Deno |
| ----------- | ------- | ------- | ---- |
| HKDF-SHA256 | ✅      |  ✅     |      |
| HKDF-SHA384 | ✅      |  ✅     |      |
| HKDF-SHA512 | ✅      |  ✅     |      |

### Authenticated Encryption with Associated Data (AEAD) Functions

| AEADs            | Browser | Node.js | Deno |
| ---------------- | ------- | ------- | ---- |
| AES-128-GCM      | ✅      |  ✅     |      |
| AES-256-GCM      | ✅      |  ✅     |      |
| ChaCha20Poly1305 | ✅      |  ✅     |      |
| Export Only      | ✅      |  ✅     |      |

## Installation

Using npm:

```
npm install hpke-js
```

Using unpkg CDN:

```html
<!-- use the latest stable version -->
<script src="https://unpkg.com/hpke-js/dist/hpke.min.js"></script>

<!-- use a specific version -->
<script src="https://unpkg.com/hpke-js@0.5.1/dist/hpke.min.js"></script>
```

Using jsDelivr CDN:

```html
<!-- use the latest stable version -->
<script src="https://cdn.jsdelivr.net/npm/hpke-js/dist/hpke.min.js"></script>

<!-- use a specific version -->
<script src="https://cdn.jsdelivr.net/npm/hpke-js@0.5.1/dist/hpke.min.js"></script>
```

## Usage

This section shows some typical usage examples.

### Base mode

On browser:

```html
<html>
  <head></head>
  <body>
    <script src="https://unpkg.com/hpke-js/dist/hpke.min.js"></script>
    <script type="text/javascript">

      async function doHpke() {

        // the global name is 'hkpe'
        const suite = new hpke.CipherSuite({
          kem: hpke.Kem.DhkemP256HkdfSha256,
          kdf: hpke.Kdf.HkdfSha256,
          aead: hpke.Aead.Aes128Gcm
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
        const ct = await sender.seal(new TextEncoder().encode('hello world!'));
      
        // decrypt
        const pt = await recipient.open(ct);

        // hello world!
        alert(new TextDecoder().decode(pt));
      }
      
    </script>
    <button type="button" onclick="doHpke()">do HPKE</button>
  </body>
</html>
```

On Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {

  // setup
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
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  const pt = await recipient.open(ct);

  console.log("decrypted: ", new TextDecoder().decode(pt));
  // decripted: my-secret-message
}

doHpke();
```

### Base mode with Single-Shot APIs

On Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

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
  const pt = await suite.open({ recipientKey: rkp, enc: enc }, ct);

  console.log("decrypted: ", new TextDecoder().decode(pt));
  // decripted: my-secret-message
}

doHpke();
```

### Base mode with bidirectional encryption

On Node.js:

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
  await sender.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));
  await recipient.setupBidirectional(te.encode('seed-for-key'), te.encode('seed-for-nonce'));

  // encrypt
  const ct = await sender.seal(te.encode('my-secret-message-s'));

  // decrypt
  const pt = await recipient.open(ct);

  console.log("recipient decrypted: ", td.decode(pt));

  // decripted: my-secret-message-s
  // encrypt reversely
  const rct = await recipient.seal(te.encode('my-secret-message-r'));

  // decrypt reversely
  const rpt = await sender.open(rct);

  console.log("sender decrypted: ", td.decode(rpt));
  // decripted: my-secret-message-r
}

doHpke();
```

### Base mode with export-only AEAD

On Node.js:

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

On Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      key: new TextEncoder().encode("our-pre-shared-key"),
    }
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      key: new TextEncoder().encode("our-pre-shared-key"),
    }
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  const pt = await recipient.open(ct);

  console.log("decrypted: ", new TextDecoder().decode(pt));
  // decripted: my-secret-message
}

doHpke();
```

### Auth mode

On Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm
  });

  const rkp = await suite.generateKeyPair();
  const skp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
    senderPublicKey: skp.publicKey
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  const pt = await recipient.open(ct);

  console.log("decrypted: ", new TextDecoder().decode(pt));
  // decripted: my-secret-message
}

doHpke();
```

### AuthPSK mode

On Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm
  });

  const rkp = await suite.generateKeyPair();
  const skp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      key: new TextEncoder().encode("our-pre-shared-key"),
    }
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
    senderPublicKey: skp.publicKey,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      key: new TextEncoder().encode("our-pre-shared-key"),
    }
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  const pt = await recipient.open(ct);

  console.log("decrypted: ", new TextDecoder().decode(pt));
  // decripted: my-secret-message
}

doHpke();
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or sending PRs.

## References

- [RFC9180: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/rfc9180)
