<h1 align="center">@hpke/ml-kem</h1>

<div align="center">
<a href="https://jsr.io/@hpke/ml-kem"><img src="https://jsr.io/badges/@hpke/ml-kem" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-hpke-mlkem/">ML-KEM for HPKE</a>.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/ml-kem/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/ml-kem/docs/)

</div>

An example of use:

```ts
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { MlKem768 } from "@hpke/ml-kem"; // MlKem512 and MlKem1024 are also available.

async function doHpke() {
  const suite = new CipherSuite({
    kem: new MlKem768(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  // NOTE: The following support for JWKs with the AKP key type is experimental.
  // Please be aware that the specifications are subject to change without notice.
  const jwkPub = {
    kty: "AKP",
    kid: "01",
    alg: "ML-KEM-768",
    pub:
      "PxuKXPWqDLFIz6x2ajCnggmjzpfLQnqegTJU4LapmuJTcLWDwnU1fOO01sYKr9oD6Zc04OmOulau74IekrjB20OUKnw3yZd9eZRv4EdN8nuc87EsqUuwZAHQkVBTC_gq38RiO9evl0JZhLjFP1GWnrwC2bQarOeVNuMoKvWt7bY2PUp727BqaeJMiSiI9nEAVbtkTbYLo7iEIEwDsHwqisoCSawp6td9XIeaeQoJuFClXvYUzHPPf3JyI7oNY1MpXACMmGqpIANJoKxQDjR-4XlaGoNpq2FRwnsTQcrOVoUu52xtPMuDMbI83osiSvmy3uQC2WBbv6hAGXZBnFerFoa9oJayjLZUzUpdt8MlmOAUkeIbjNVEl_YP4rwx14OSjjgr-_MzK3VM-WmxKqWPQ4tKVwZBKdRFYAmhcqWas7d8yEx2lEuZpTRFpSmsCmKtSQF0pHMkpdNLgaaCppwKjddfDek8IOQwJmwjsAxIafU8b9CFTtPK9FRJUrBe07Ow1so08PKX8umnwRh4BKN6Ehpq0qtQ2vR1qjol5smg1qKd72LL0pgFD1swfAU6XIg4tMM1fzN2ZTwzZvpv4QJdGWDHW6ZDJlwVeoTJFNVZ9UDGfsFYc5Sve9F4MNUInVBZBvqfdmqbk5CfW2YnzAWgshksv8InGwsi13oHzlUe2qZSLUArAAA3I8EVk2yX9UyIqlE0gqBVVMYo5pRI62oO9vNGNByAK9q5sDugryl9nouTi5yr76RnIkIaM4qHLZqIuIyfDuxGkyw2fMWLg1c9JgNqr1J25RWw8jBZtAyEj2OKzjcD7mwn2WaZDHcC7SOgzZukz2Fppmih8LtYawdmkuHCFXVP9nhL2RokjLkPAIo-ylmFLAV5ZpM6Goa24FsvrZGyi8YWSLBBp6wEargRK2rCy5APtcCYIdxLBxa1CeEi3JfG7XNC9vSftlVZcpw4R2O6LSu4z1auNvOyaZcKxUhBITskt5LJSfPHdecKyPfMU3Y_9jitxRE-xgB1waeSdspHPBE4MpVKviB76_DNBCbA4pczlHJWx3Vr-bUNghkaB_C6XVoVSwhm4pNHO0B2oemV-dCGpHLBGKwiwhaoOZIGYKMx7uGY31saFZUjnVeAzadfc8Z2WkauSqNAAZOd-tkvfhJKXyxiiyWd6VYLv0cMxpzGUtwpuTuoakmQ3OCvGkUkwZmmkmcMr3SNFmEv7tcR-IpQXVUqZECqBCJibxhfaSGoLvklCGAoroVi_HYQ4bFknvAJTZa1Bfu38RKJbvrA0ZKvRdkDrHmSu-m_MOJXfiRYHLxPc7GA0Epp9UCznhmkrjauxPIa3ndJZTkbyuvAr4actjYxMntCG-xnJmUbh1i_7nPFkSEtT_mB9mhMWLNZwtB_oeYB1sXL_clksxkJzKN__5YgT7VojZLKWoV1jPFg6bBu0YMgpLGwyOgZaudqb2IZctF6TWSn3wTFpMMzw7wayqs3cJFJo7jKCCqPvKEyaKGwIiMOLWMCcsuf8uZlWvFzJ_O5gHCV9YK-GL0_Tgu3I-ztabBYVimYZUjXIrA7W70Vesmd7hwKmqE",
    key_ops: [],
  };
  const pk = await suite.kem.importKey("jwk", jwkPub, true);
  // In addition to importing keys from external sources, you can also generate keys as follows:
  //   const rkp = await suite.kem.generateKeyPair();
  //   const rkp = await suite.kem.deriveKeyPair(random64bytesValue);

  const sender = await suite.createSenderContext({ recipientPublicKey: pk });

  const jwkPriv = {
    kty: "AKP",
    kid: "01",
    alg: "ML-KEM-768",
    priv:
      "1pz8ZPhNTzPkxU4Wa3_5KDo5SYalObI5h6EPOdLZaJtt5i40ZaVcnHigfSZb6FQLPliwgBoSTQf_ErQ41SAuoA",
    key_ops: ["deriveBits"],
  };
  const sk = await suite.kem.importKey("jwk", jwkPriv, false);
  const recipient = await suite.createRecipientContext({
    recipientKey: sk,
    enc: sender.enc,
  });
  const encrypted = await sender.seal(
    new TextEncoder().encode("Hellow world!"),
  );
  const pt = await recipient.open(encrypted);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (err: unknown) {
  console.log("failed:", (err as Error).message);
}
```

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

`@hpke/ml-kem` needs to be used with
[@hpke/core](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md),
which can be installed in the same manner as desribed below.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/ml-kem
yarn add @hpke/ml-kem
pnpm install @hpke/ml-kem
# Using jsr:
npx jsr add @hpke/ml-kem
yarn dlx jsr add @hpke/ml-kem
pnpm dlx jsr add @@hpke/ml-kem
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { MlKem768 } from "@hpke/ml-kem";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/ml-kem
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core@<SEMVER>";
  import { MlKem768 } from "https://esm.sh/@hpke/ml-kem@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core";
  import { MlKem768 } from "https://esm.sh/@hpke/ml-kem";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://unpkg.com/@hpke/core@<SEMVER>/esm/mod.js";
  import { MlKem768 } from "https://unpkg.com/@hpke/ml-kem@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { MlKem768 } from "@hpke/ml-kem";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new MlKem768(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // Note that the `ct` (ciphertext) resulting from ML-KEM::Encaps() is set to `sender.enc`.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const encrypted = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc, // == `ct` (ciphertext) in the context of ML-KEM
  });

  // decrypt
  const pt = await recipient.open(encrypted);

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
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { MlKem768 } from "@hpke/ml-kem";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new MlKem768(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // Note that the `ct` (ciphertext) resulting from ML-KEM::Encaps() is set to `sender.enc`.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const encrypted = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc, // == `ct` (ciphertext) in the context of ML-KEM
  });

  // decrypt
  const pt = await recipient.open(encrypted);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (_err: unknown) {
  console.log("failed.");
}
```

### Web Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import {
        Aes256Gcm,
        CipherSuite,
        HkdfSha256,
      } from "https://esm.sh/@hpke/core";
      import { MlKem768 } from "https://esm.sh/@hpke/ml-kem";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new MlKem768(),
            kdf: new HkdfSha256(),
            aead: new Aes256Gcm(),
          });

          const rkp = await suite.kem.generateKeyPair();

          // Note that the `ct` (ciphertext) resulting from ML-KEM::Encaps() is set to `sender.enc`.
          const sender = await suite.createSenderContext({
            recipientPublicKey: rkp.publicKey,
          });
          // encrypt
          const encrypted = await sender.seal(
            new TextEncoder().encode("Hello world!"),
          );

          const recipient = await suite.createRecipientContext({
            recipientKey: rkp.privateKey, // rkp (CryptoKeyPair) is also acceptable.
            enc: sender.enc, // == `ct` (ciphertext) in the context of ML-KEM
          });

          // decrypt
          const pt = await recipient.open(encrypted);

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
