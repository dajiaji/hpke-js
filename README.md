<h1 align="center">hpke-js</h1>

<div align="center">

[![Stable Release](https://img.shields.io/npm/v/hpke-js.svg)](https://npm.im/hpke-js)
![Github CI](https://github.com/dajiaji/hpke-js/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/hpke-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2)](https://codecov.io/gh/dajiaji/hpke-js)

</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation build on top of <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>.
This library works both on web browsers and Node.js. <b>Currently, Deno is not supported.</b>
</div>

<p></p>

<div align="center">

[API Documentation](https://dajiaji.github.io/hpke-js/)

</div>

## Index

- [Supported Features](#supported-features)
- [Supported Environments](#supported-environments)
- [Warnings and Restrictions](#warnings-and-restrictions)
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

| KEMs                        | Browser | Node.js | Deno |      |
| --------------------------- | ------- | ------- | ---- | ---- |
| DHKEM (P-256, HKDF-SHA256)  | ✅      |  ✅     |      |      |
| DHKEM (P-384, HKDF-SHA384)  | ✅      |  ✅     |      |      |
| DHKEM (P-521, HKDF-SHA512)  | ✅      |  ✅     |      |      |
| DHKEM (X25519, HKDF-SHA256) | ✅      |  ✅     |      | [@stablelib/x25519](https://www.stablelib.com/modules/_x25519_x25519_.html) is used <br>until [Secure Curves](https://wicg.github.io/webcrypto-secure-curves/) is implemented <br>on browsers. |
| DHKEM (X448, HKDF-SHA512)   | ✅      |  ✅     |      | [x449-js](https://github.com/Iskander508/X448-js) is used <br>until [Secure Curves](https://wicg.github.io/webcrypto-secure-curves/) is implemented <br>on browsers. |

### Key Derivation Functions (KDFs)

| KDFs        | Browser | Node.js | Deno |      |
| ----------- | ------- | ------- | ---- | ---- |
| HKDF-SHA256 | ✅      |  ✅     |      |      |
| HKDF-SHA384 | ✅      |  ✅     |      |      |
| HKDF-SHA512 | ✅      |  ✅     |      |      |

### Authenticated Encryption with Associated Data (AEAD) Functions

| AEADs            | Browser | Node.js | Deno |      |
| ---------------- | ------- | ------- | ---- | ---- |
| AES-128-GCM      | ✅      |  ✅     |      |      |
| AES-256-GCM      | ✅      |  ✅     |      |      |
| ChaCha20Poly1305 | ✅      |  ✅     |      | [@stablelib/chacha20poly1305](https://www.stablelib.com/modules/_chacha20poly1305_chacha20poly1305_.html) is used. |
| Export Only      | ✅      |  ✅     |      |      |

## Supported Environments

- __Web Browser__: [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/) supported browsers
    - Confirmed: Chrome, Firefox, Edge, Safari, Opera, Vivaldi, Brave
- __Node.js__: 16.x, 17.x, 18.x

## Warnings and Restrictions

- Although this library has been passed the following test vectors, it has not been formally audited.
    - [RFC9180 official test vectors provided on github.com/cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json)
    - [ECDH/X25519/X449 test vectors provided on Project Wycheproof](https://github.com/google/wycheproof)
- The upper limit of the AEAD sequence number is further rounded to JavaScript's MAX\_SAFE\_INTEGER (`2^53-1`).

## Installation

Using npm:

```
npm install hpke-js
```

Using yarn:

```
yarn add hpke-js
```

Using unpkg CDN:

```html
<!-- use the latest stable version -->
<script src="https://unpkg.com/hpke-js/dist/hpke.min.js"></script>

<!-- use a specific version -->
<script src="https://unpkg.com/hpke-js@0.9.1/dist/hpke.min.js"></script>
```

Using jsDelivr CDN:

```html
<!-- use the latest stable version -->
<script src="https://cdn.jsdelivr.net/npm/hpke-js/dist/hpke.min.js"></script>

<!-- use a specific version -->
<script src="https://cdn.jsdelivr.net/npm/hpke-js@0.9.1/dist/hpke.min.js"></script>
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
const { Kem, Kdf, Aead, CipherSuite } = require('hpke-js');

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
  const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

  // decrypt
  const pt = await recipient.open(ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
}

doHpke();
```

### Base mode with Single-Shot APIs

On Node.js:

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
  const pt = await suite.open({ recipientKey: rkp, enc: enc }, ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
}

doHpke();
```

### Base mode with bidirectional encryption

On Node.js:

```js
const { Kem, Kdf, Aead, CipherSuite } = require('hpke-js');

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

  console.log('recipient decrypted: ', td.decode(pt));
  // decrypted: my-secret-message-s

  // encrypt reversely
  const rct = await recipient.seal(te.encode('my-secret-message-r'));

  // decrypt reversely
  const rpt = await sender.open(rct);

  console.log('sender decrypted: ', td.decode(rpt));
  // decrypted: my-secret-message-r
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
const { Kem, Kdf, Aead, CipherSuite } = require('hpke-js');

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
      id: new TextEncoder().encode('our-pre-shared-key-id'),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode('jugemujugemugokounosurikirekaija'),
    }
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
    psk: {
      id: new TextEncoder().encode('our-pre-shared-key-id'),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode('jugemujugemugokounosurikirekaija'),
    }
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

  // decrypt
  const pt = await recipient.open(ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
}

doHpke();
```

### Auth mode

On Node.js:

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
  const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

  // decrypt
  const pt = await recipient.open(ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
}

doHpke();
```

### AuthPSK mode

On Node.js:

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
  const skp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
    senderKey: skp,
    psk: {
      id: new TextEncoder().encode('our-pre-shared-key-id'),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode('jugemujugemugokounosurikirekaija'),
    }
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
    senderPublicKey: skp.publicKey,
    psk: {
      id: new TextEncoder().encode('our-pre-shared-key-id'),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode('jugemujugemugokounosurikirekaija'),
    }
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode('my-secret-message'));

  // decrypt
  const pt = await recipient.open(ct);

  console.log('decrypted: ', new TextDecoder().decode(pt));
  // decrypted: my-secret-message
}

doHpke();
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or sending PRs.

## References

- [RFC9180: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/rfc9180)
- [W3C/WICG: Secure Curves in the Web Cryptography API](https://wicg.github.io/webcrypto-secure-curves/)
