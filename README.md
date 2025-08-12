<h1 align="center">hpke-js</h1>

<div align="center">
<a href="https://jsr.io/@hpke/hpke-js"><img src="https://jsr.io/badges/@hpke/hpke-js" alt="JSR"/></a>
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_browser.yml/badge.svg" alt="Browser CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_node.yml/badge.svg" alt="Node.js CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci.yml/badge.svg" alt="Deno CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_cloudflare.yml/badge.svg" alt="Cloudflare Workers CI" />
<img src="https://github.com/dajiaji/hpke-js/actions/workflows/ci_bun.yml/badge.svg" alt="bun CI" />
<a href="https://codecov.io/gh/dajiaji/hpke-js">
  <img src="https://codecov.io/gh/dajiaji/hpke-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2" alt="codecov" />
</a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a>
implementation build on top of <a href="https://www.w3.org/TR/WebCryptoAPI/">Web Cryptography API</a>.
This module works on web browsers, Node.js, Deno and various other JavaScript runtimes.
</div>

<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/core/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/core/docs/)

</div>

For Node.js, you can install `@hpke/core` and other extensions via npm, yarn,
pnpm or jsr:

```sh
# Using npm:
npm install @hpke/core
yarn add @hpke/core
pnpm install @hpke/core
# Using jsr:
npx jsr add @hpke/core
yarn dlx jsr add @hpke/core
pnpm dlx jsr add @hpke/core
```

Following extensions can be installed in the same manner:

- `@hpke/chacha20poly1305`
- `@hpke/dhkem-x25519`
- `@hpke/dhkem-x448`
- `@hpke/dhkem-secp256k1`
- `@hpke/hybridkem-x-wing`
- `@hpke/ml-kem`
- `@hpke/hybridkem-x25519-kyber768` - deprecated

Then, you can use it as follows:

```js
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

async function doHpke() {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
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
  const pt = await recipient.open(ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (e) {
  console.log("failed:", e.message);
}
```

## Index

- [Packages](#packages)
- [Supported Features](#supported-features)
- [Supported Environments](#supported-environments)
- [Warnings and Restrictions](#warnings-and-restrictions)
- [Contributing](#contributing)
- [References](#references)

## Packages

The hpke-js includes the following packages.

| name                                         | registry                                                                                                                                                                                                                                                                  | description                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| @hpke/core                                   | [![npm](https://img.shields.io/npm/v/@hpke/core?color=%23EE3214)](https://www.npmjs.com/package/@hpke/core)<br/>[![JSR](https://jsr.io/badges/@hpke/core)](https://jsr.io/@hpke/core)                                                                                     | The HPKE core module implemented using only [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/). It does not support the X25519/X448-based KEMs and the ChaCha20/Poly1305 AEAD, but it has no external module dependencies. It's small in size and tree-shaking friendly.<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/core/samples) |
| @hpke/chacha20poly1305                       | [![npm](https://img.shields.io/npm/v/@hpke/chacha20poly1305?color=%23EE3214)](https://www.npmjs.com/package/@hpke/chacha20poly1305)<br/>[![JSR](https://jsr.io/badges/@hpke/chacha20poly1305)](https://jsr.io/@hpke/chacha20poly1305)                                     | The HPKE module extension for ChaCha20Poly1305 AEAD.<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/chacha20poly1305/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/chacha20poly1305/samples)                                                                                                                                                                                                      |
| @hpke/dhkem-x25519                           | [![npm](https://img.shields.io/npm/v/@hpke/dhkem-x25519?color=%23EE3214)](https://www.npmjs.com/package/@hpke/dhkem-x25519)<br/>[![JSR](https://jsr.io/badges/@hpke/dhkem-x25519)](https://jsr.io/@hpke/dhkem-x25519)                                                     | The HPKE module extension for DHKEM(X25519, HKDF-SHA256).<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/dhkem-x25519/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/dhkem-x25519/samples)                                                                                                                                                                                                         |
| @hpke/dhkem-x448                             | [![npm](https://img.shields.io/npm/v/@hpke/dhkem-x448?color=%23EE3214)](https://www.npmjs.com/package/@hpke/dhkem-x448)<br/>[![JSR](https://jsr.io/badges/@hpke/dhkem-x448)](https://jsr.io/@hpke/dhkem-x448)                                                             | The HPKE module extension for DHKEM(X448, HKDF-SHA512).<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/dhkem-x448/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/dhkem-x448/samples)                                                                                                                                                                                                               |
| hpke-js                                      | [![npm](https://img.shields.io/npm/v/hpke-js?color=%23EE3214)](https://www.npmjs.com/package/hpke-js)                                                                                                                                                                     | The HPKE module supporting all of the ciphersuites defined in [RFC9180](https://datatracker.ietf.org/doc/html/rfc9180), which consists of the above @hpke/{core, dhkem-x25519, dhkem-x448, chacha20poly1305} internally.<br/>[README](https://github.com/dajiaji/hpke-js/tree/main/packages/hpke-js/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/hpke-js/samples)                                                    |
| @hpke/hpke-js                                | [![JSR](https://jsr.io/badges/@hpke/hpke-js)](https://jsr.io/@hpke/hpke-js)                                                                                                                                                                                               | The JSR version of the above `hpke-js`.<br/>[README](https://github.com/dajiaji/hpke-js/tree/main/packages/hpke-js/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/hpke-js/samples)                                                                                                                                                                                                                                     |
| @hpke/ml-kem                                 | [![npm](https://img.shields.io/npm/v/@hpke/ml-kem?color=%23EE3214)](https://www.npmjs.com/package/@hpke/ml-kem)<br/>[![JSR](https://jsr.io/badges/@hpke/ml-kem)](https://jsr.io/@hpke/ml-kem)                                                                             | **EXPERIMENTAL AND NOT STANDARDIZED**<br/>The HPKE module extension for [ML-KEM](https://datatracker.ietf.org/doc/draft-connolly-cfrg-hpke-mlkem/).<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/ml-kem/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/ml-kem/samples)                                                                                                                           |
| @hpke/hybridkem-x-wing                       | [![npm](https://img.shields.io/npm/v/@hpke/hybridkem-x-wing?color=%23EE3214)](https://www.npmjs.com/package/@hpke/hybridkem-x-wing)<br/>[![JSR](https://jsr.io/badges/@hpke/hybridkem-x-wing)](https://jsr.io/@hpke/hybridkem-x-wing)                                     | **EXPERIMENTAL AND NOT STANDARDIZED**<br/>The HPKE module extension for [X-Wing: general-purpose hybrid post-quantum KEM](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/hybridkem-x-wing/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/hybridkem-x-wing/samples)                                                               |
| @hpke/hybridkem-x25519-kyber768 (deprelated) | [![npm](https://img.shields.io/npm/v/@hpke/hybridkem-x25519-kyber768?color=%23EE3214)](https://www.npmjs.com/package/@hpke/hybridkem-x25519-kyber768)<br/>[![JSR](https://jsr.io/badges/@hpke/hybridkem-x25519-kyber768)](https://jsr.io/@hpke/hybridkem-x25519-kyber768) | **EXPERIMENTAL AND NOT STANDARDIZED**<br/>The HPKE module extension for the hybrid post-quantum KEM currently named [X25519Kyber768Draft00](https://datatracker.ietf.org/doc/draft-westerbaan-cfrg-hpke-xyber768d00/).<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/hybridkem-x25519-kyber768/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/hybridkem-x25519-kyber768/samples)                  |
| @hpke/dhkem-secp256k1                        | [![npm](https://img.shields.io/npm/v/@hpke/dhkem-secp256k1?color=%23EE3214)](https://www.npmjs.com/package/@hpke/dhkem-secp256k1)<br/>[![JSR](https://jsr.io/badges/@hpke/dhkem-secp256k1)](https://jsr.io/@hpke/dhkem-secp256k1)                                         | **EXPERIMENTAL AND NOT STANDARDIZED**<br/>The HPKE module extension for DHKEM(secp256k1, HKDF-SHA256).<br/>[README](https://github.com/dajiaji/hpke-js/blob/main/packages/dhkem-secp256k1/README.md) / [samples](https://github.com/dajiaji/hpke-js/tree/main/packages/dhkem-secp256k1/samples)                                                                                                                                                      |

## Supported Features

### HPKE Modes

| Base | PSK | Auth | AuthPSK |
| ---- | --- | ---- | ------- |
| ✅   | ✅  | ✅   | ✅      |

### Key Encapsulation Machanisms (KEMs)

| KEMs                           | Browser                               | Node.js                               | Deno                                  | Cloudflare<br>Workers                 | bun                                   |
| ------------------------------ | ------------------------------------- | ------------------------------------- | ------------------------------------- | ------------------------------------- | ------------------------------------- |
| DHKEM (P-256, HKDF-SHA256)     | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           |
| DHKEM (P-384, HKDF-SHA384)     | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           |
| DHKEM (P-521, HKDF-SHA512)     | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           |                                       | ✅<br>hpke-js<br>@hpke/core           | ✅<br>hpke-js<br>@hpke/core           |
| DHKEM (X25519, HKDF-SHA256)    | ✅<br>hpke-js<br>@hpke/dhkem-x25519   | ✅<br>hpke-js<br>@hpke/dhkem-x25519   | ✅<br>hpke-js<br>@hpke/dhkem-x25519   | ✅<br>hpke-js<br>@hpke/dhkem-x25519   | ✅<br>hpke-js<br>@hpke/dhkem-x25519   |
| DHKEM (X448, HKDF-SHA512)      | ✅<br>hpke-js<br>@hpke/dhkem-x448     | ✅<br>hpke-js<br>@hpke/dhkem-x448     | ✅<br>hpke-js<br>@hpke/dhkem-x448     | ✅<br>hpke-js<br>@hpke/dhkem-x448     | ✅<br>hpke-js<br>@hpke/dhkem-x448     |
| ML-KEM-512                     | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    |
| ML-KEM-768                     | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    |
| ML-KEM-1024                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    | ✅<br>@hpke/ml-kem                    |
| X-Wing                         | ✅<br>@hpke/hybridkem-x-wing          | ✅<br>@hpke/hybridkem-x-wing          | ✅<br>@hpke/hybridkem-x-wing          | ✅<br>@hpke/hybridkem-x-wing          | ✅<br>@hpke/hybridkem-x-wing          |
| Hybrid KEM (X25519, Kyber768)  | ✅<br>@hpke/hybridkem-x25519-kyber768 | ✅<br>@hpke/hybridkem-x25519-kyber768 | ✅<br>@hpke/hybridkem-x25519-kyber768 | ✅<br>@hpke/hybridkem-x25519-kyber768 | ✅<br>@hpke/hybridkem-x25519-kyber768 |
| DHKEM (secp256k1, HKDF-SHA256) | ✅<br>@hpke/dhkem-secp256k1           | ✅<br>@hpke/dhkem-secp256k1           | ✅<br>@hpke/dhkem-secp256k1           | ✅<br>@hpke/dhkem-secp256k1           | ✅<br>@hpke/dhkem-secp256k1           |

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
- **Node.js**: 16.x, 17.x, 18.x, 19.x, 20.x, 21.x, 22.x, 23.x, 24.x
- **Deno**: 2.x
- **Cloudflare Workers**
- **bun**: 0.x (0.6.0-), 1.x

## Warnings and Restrictions

- Although this library has been passed the following test vectors, it has not
  been formally audited.
  - [RFC9180 official test vectors provided on github.com/cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json)
  - [ECDH/X25519/X448 test vectors provided on Project Wycheproof](https://github.com/google/wycheproof)
- The upper limit of the AEAD sequence number is further rounded to JavaScript's
  MAX\_SAFE\_INTEGER (`2^53-1`).

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs. Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed
guidelines on:

- Development setup and prerequisites
- Available development tasks
- Code quality requirements
- Project structure
- Testing requirements
- Documentation guidelines

## References

- [W3C: Web Cryptography API](https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/)
- [W3C/WICG: Secure Curves in the Web Cryptography API](https://wicg.github.io/webcrypto-secure-curves/)
- [W3C: Web Cryptography API Level 2](https://w3c.github.io/webcrypto/)
- [IETF/HPKE-WG: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/draft-ietf-hpke-hpke/)
- [IETF/HPKE-WG: Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq)
- [IRTF/CFRG: RFC9180: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/rfc9180)
- [IRTF/CFRG: X25519Kyber768Draft00 hybrid post-quantum KEM for HPKE](https://datatracker.ietf.org/doc/html/draft-westerbaan-cfrg-hpke-xyber768d00)
- [IRTF/CFRG: X-Wing: general-purpose hybrid post-quantum KEM](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem)
- [IRTF/CFRG: Hybrid PQ/T Key Encapsulation Mechanisms](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/)
- [IRTF/CFRG: Concrete Hybrid PQ/T Key Encapsulation Mechanisms](https://datatracker.ietf.org/doc/draft-irtf-cfrg-concrete-hybrid-kems/)
- [IRTF/CFRG: Deterministic Nonce-less Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/draft-irtf-cfrg-dnhpke/)
- [IRTF/CFRG: SHA-3 for HPKE](https://datatracker.ietf.org/doc/draft-connolly-cfrg-sha3-hpke/)
