<h1 align="center">hpke-js</h1>

<div align="center">A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation for browser-based applications.</div>

## Index

- [Supported Features](#supported-features)
- [Installation](#installation)
- [Usage](#usage)
  - [Base mode](#base-mode)
  - [PSK mode](#psk-mode)
  - [Auth mode](#auth-mode)
  - [AuthPSK mode](#authpsk-mode)
- [Contributing](#contributing)
- [References](#references)

## Supported Features

### HPKE Modes

| Modes   | Browser | Node.js |
| ------- | ------- | ------- |
| Base    | ✅      |  ✅     |
| PSK     | ✅      |  ✅     |
| Auth    | ✅      |  ✅     |
| AuthPSK |         |         |

### Key Encapsulation Machanisms (KEMs)

| KEMs                        | Browser | Node.js |
| --------------------------- | ------- | ------- |
| DHKEM (P-256, HKDF-SHA256)  | ✅      |  ✅     |
| DHKEM (P-384, HKDF-SHA384)  | ✅      |  ✅     |
| DHKEM (P-521, HKDF-SHA512)  | ✅      |  ✅     |
| DHKEM (X25519, HKDF-SHA256) |         |         |
| DHKEM (X448, HKDF-SHA512)   |         |         |

### Key Derivation Functions (KDFs)

| KDFs        | Browser | Node.js |
| ----------- | ------- | ------- |
| HKDF-SHA256 | ✅      |  ✅     |
| HKDF-SHA384 | ✅      |  ✅     |
| HKDF-SHA512 | ✅      |  ✅     |

### Authenticated Encryption with Associated Data (AEAD) Functions

| AEADs            | Browser | Node.js |
| ---------------- | ------- | ------- |
| AES-128-GCM      | ✅      |  ✅     |
| AES-256-GCM      | ✅      |  ✅     |
| ChaCha20Poly1305 |         |         |
| Export Only      | ✅      |  ✅     |

## Installation

Install with npm:

```
npm install hpke
```

## Usage

This section shows some typical usage examples. See [API Documentation](#) for details. 

### Base mode

On browser:

```js

// The global name is "hpke".

// setup
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
const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

// decrypt
const pt = await recipient.open(ct);

// new TextDecoder().decode(pt) === "my-secret-message"
```

### PSK mode

On browser:

```js

// The global name is "hpke".

// setup
const suite = new hpke.CipherSuite({
  kem: hpke.Kem.DhkemP256HkdfSha256,
  kdf: hpke.Kdf.HkdfSha256,
  aead: hpke.Aead.Aes128Gcm
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

// new TextDecoder().decode(pt) === "my-secret-message"
```

### Auth mode

On browser:

```js

// The global name is "hpke".

// setup
const suite = new hpke.CipherSuite({
  kem: hpke.Kem.DhkemP256HkdfSha256,
  kdf: hpke.Kdf.HkdfSha256,
  aead: hpke.Aead.Aes128Gcm
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

// new TextDecoder().decode(pt) === "my-secret-message"
```

### AuthPSK mode

On browser:

```js

// The global name is "hpke".

// setup
const suite = new hpke.CipherSuite({
  kem: hpke.Kem.DhkemP256HkdfSha256,
  kdf: hpke.Kdf.HkdfSha256,
  aead: hpke.Aead.Aes128Gcm
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

// new TextDecoder().decode(pt) === "my-secret-message"
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or sending PRs.

## References

- [RFC9180: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/rfc9180)
