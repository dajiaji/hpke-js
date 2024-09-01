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

Documentation: [jsr.io](https://jsr.io/@hpke/hpke-js/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/docs/)

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
// import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
// const { AeadId, CipherSuite, KdfId, KemId } = require("@hpke/hpke-js");
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

async function doHpke() {
  // When using "hpke-js", specify the cryptographic algorithm as follows:
  // const suite = new CipherSuite({
  //   kem: KemId.DhkemP256HkdfSha256,
  //   kdf: KdfId.HkdfSha256,
  //   aead: AeadId.Aes128Gcm,
  // });
  // When using "@hpke/core", specify the cryptographic algorithm instances
  // as follows, instead of identities above:
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
- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
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

| name                            | since   | description                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| hpke-js                         | v0.1.0- | The HPKE module supporting all of the ciphersuites defined in [RFC9180](https://datatracker.ietf.org/doc/html/rfc9180), which consists of the following @hpke/{core, dhkem-x25519, dhkem-x448, chacha20poly1305} internally.                                                                                                                                       |
| @hpke/core                      | v1.0.0- | The HPKE core module implemented using only [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI/). It does not support the X25519/X448-based KEMs and the ChaCha20/Poly1305 AEAD, but it has no external module dependencies. It's small in size and tree-shaking friendly. See [/core/README](https://github.com/dajiaji/hpke-js/blob/main/core/README.md). |
| @hpke/chacha20poly1305          | v1.0.0- | The HPKE module extension for ChaCha20Poly1305 AEAD. See [/x/chacha20poly1305/README](https://github.com/dajiaji/hpke-js/blob/main/x/chacha20poly1305/README.md).                                                                                                                                                                                                  |
| @hpke/dhkem-x25519              | v1.0.0- | The HPKE module extension for DHKEM(X25519, HKDF-SHA256). See [/x/dhkem-x25519/README](https://github.com/dajiaji/hpke-js/blob/main/x/dhkem-x25519/README.md).                                                                                                                                                                                                     |
| @hpke/dhkem-x448                | v1.0.0- | The HPKE module extension for DHKEM(X448, HKDF-SHA512). See [/x/dhkem-x448/README](https://github.com/dajiaji/hpke-js/blob/main/x/dhkem-x448/README.md).                                                                                                                                                                                                           |
| @hpke/hybridkem-x25519-kyber768 | v1.2.1- | **EXPERIMENTAL AND NOT STANDARDIZED** The HPKE module extension for the hybrid post-quantum KEM currently named [X25519Kyber768Draft00](https://datatracker.ietf.org/doc/draft-westerbaan-cfrg-hpke-xyber768d00/). See [/x/hybridkem-x25519-kyber768/README](https://github.com/dajiaji/hpke-js/blob/main/x/hybridkem-x25519-kyber768/README.md).                  |
| @hpke/dhkem-secp256k1           | v1.0.0- | **EXPERIMENTAL AND NOT STANDARDIZED** The HPKE module extension for DHKEM(secp256k1, HKDF-SHA256). See [/x/dhkem-secp256k1/README](https://github.com/dajiaji/hpke-js/blob/main/x/dhkem-secp256k1/README.md).                                                                                                                                                      |

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
- **Node.js**: 16.x, 17.x, 18.x, 19.x, 20.x
- **Deno**: 1.x (1.25-)
- **Cloudflare Workers**
- **bun**: 0.x (0.6.0-), 1.x

## Warnings and Restrictions

- Although this library has been passed the following test vectors, it has not
  been formally audited.
  - [RFC9180 official test vectors provided on github.com/cfrg/draft-irtf-cfrg-hpke](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json)
  - [ECDH/X25519/X448 test vectors provided on Project Wycheproof](https://github.com/google/wycheproof)
- The upper limit of the AEAD sequence number is further rounded to JavaScript's
  MAX\_SAFE\_INTEGER (`2^53-1`).

## Installation

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

Starting from version 1.3.0, hpke-js packages are available from the JSR
registry. From this version onwards, please use JSR import instead of HTTPS
import in Deno.

**JSR imoprt (recommended on `>=1.3.0`):**

Add hpke-js packages using the commands below:

```sh
deno add @hpke/hpke-js
```

Then, you can use the module from code like this:

```ts
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
```

**HTTPS imoprt (deprecated):**

```ts
import {
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "https://deno.land/x/hpke/core/mod.ts";
import { Chacha20Poly1305 } from "https://deno.land/x/hpke/x/chacha20poly1305/mod.ts";
```

### Web Browsers

Followings are how to use the module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://esm.sh/hpke-js@<SEMVER>";
  // import * as hpke from "https://esm.sh/@hpke/core@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import * as hpke from "https://esm.sh/hpke-js";
  // import * as hpke from "https://esm.sh/@hpke/core";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import * as hpke from "https://unpkg.com/hpke-js@<SEMVER>/esm/mod.js";
  // import * as hpke from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  // ...
</script>
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

Node.js:

```js
// import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";
// const { AeadId, CipherSuite, KdfId, KemId } = require("hpke-js");
import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

async function doHpke() {
  // When using "hpke-js":
  // const suite = new CipherSuite({
  //   kem: KemId.DhkemP256HkdfSha256,
  //   kdf: KdfId.HkdfSha256,
  //   aead: AeadId.Aes128Gcm,
  // });
  // When using "@hpke/core":
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
  console.log("decrypted: ", new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (e) {
  console.log("failed:", e.message);
}
```

Deno:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
  // When using "@hpke/hpke-js", you can specify the identifier as follows:
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });
  // When using "@hpke/core" and @hpke/dhkem-x25519, specify the instances as follows:
  // const suite = new CipherSuite({
  //   kem: new DhkemX25519HkdfSha256(),
  //   kdf: new HkdfSha256(),
  //   aead: new Aes128Gcm(),
  // });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
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

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
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

Browsers:

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import { AeadId, CipherSuite, KdfId, KemId } from "https://esm.sh/hpke-js@<SEMVER>";
      // import {
      //   Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256,
      // } from "https://esm.sh/@hpke/core@<SEMVER>";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: KemId.DhkemP256HkdfSha256,
            kdf: KdfId.HkdfSha256,
            aead: AeadId.Aes128Gcm
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
          alert("failed:", err.message);
        }
      }
      
    </script>
    <button type="button" onclick="doHpke()">do HPKE</button>
  </body>
</html>
```

### Base mode with Single-Shot APIs

Deno:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.kem.generateKeyPair();
  const pt: ArrayBuffer = new TextEncoder().encode("Hello world!");

  // encrypt
  const { ct, enc } = await suite.seal(
    { recipientPublicKey: rkp.publicKey },
    pt,
  );

  // decrypt
  const dt = await suite.open({ recipientKey: rkp.privateKey, enc: enc }, ct);

  // Hello world!
  console.log(new TextDecoder().decode(dt));
}

try {
  doHpke();
} catch (err) {
  console.log("failed:", err.message);
}
```

### Base mode with export-only AEAD

Deno:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
  // When using "hpke-js":
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

try {
  doHpke();
} catch (err) {
  console.log("failed:", err.message);
}
```

### PSK mode

Node.js:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
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

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
    psk: {
      id: new TextEncoder().encode("our-pre-shared-key-id"),
      // a PSK MUST have at least 32 bytes.
      key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
    },
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

### Auth mode

Deno:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
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

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
    senderPublicKey: skp.publicKey,
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

### AuthPSK mode

Deno:

```ts
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
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

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

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

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.

## References

- [RFC9180: Hybrid Public Key Encryption](https://datatracker.ietf.org/doc/html/rfc9180)
- [W3C/WICG: Secure Curves in the Web Cryptography API](https://wicg.github.io/webcrypto-secure-curves/)
