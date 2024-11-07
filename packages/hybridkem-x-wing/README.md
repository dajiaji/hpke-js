<h1 align="center">@hpke/hybridkem-x-wing</h1>

<div align="center">
<a href="https://jsr.io/@hpke/hybridkem-x-wing"><img src="https://jsr.io/badges/@hpke/hybridkem-x-wing" alt="JSR"/></a>
</div>

<div align="center">
A TypeScript <a href="https://datatracker.ietf.org/doc/html/rfc9180">Hybrid Public Key Encryption (HPKE)</a> module extension for <a href="https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html">X-Wing: general-purpose hybrid post-quantum KEM</a>.
</div>
<p></p>

<div align="center">

Documentation: [jsr.io](https://jsr.io/@hpke/hybridkem-x-wing/doc) |
[pages (only for the latest ver.)](https://dajiaji.github.io/hpke-js/hybridkem-x-wing/docs/)

</div>

An example of use:

```ts
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  const suite = new CipherSuite({
    kem: new XWing(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  // NOTE: The following support for JWKs with the AKP key type is experimental.
  // Please be aware that the specifications are subject to change without notice.
  const jwkPub = {
    kty: "AKP",
    kid: "01",
    alg: "X-Wing",
    pub:
      "4iNrNajCSzmxCqEyOpapGaLO2IQAYzp7BxMXE_wUsrWxnPw9pfoaksSfJVE-D9MNaxYRyauWNdcIZyekt9IdNCROZpac8Vs7KnhTKfYbCWsnfqA3ODR5prVW3nIx_kt_qcmsJMBpmgAYpSU0AbrPqQXKgWVz5WotLgZ-m3KHUzuhOpN97bMfpEus7UB2mSNhADSuMeYZoXAkUZmzxcOYZIWf4bTJcXoHwwSVvfuYoKACzPVsEobO9QQd7ePETPFr9WLHRIUYAms9i5lAaAq9OKFXX9J7WNoGO_rDLDnDCGk3TAXBrrGJi2swPMaL5FU0buCvaZY2IkoUjKKuoQRjERxwn2m2nHDOhTh0ZpjExgqa7wAwx5JM7sQqXTaBb1RerhMpNGCzrLN-oOE9cOSqeGhto5ioOXwI6vloghE_5Pe61NpAsFAeHHU-_nMFPIcBToZhwzCZr-i-3kFKWxqifYOSs-Ex6acMEFWHgkDK0PQNX-PN-FI26tl-KpdEg2OygIyq_VFs0lBSxcNiVDwlF-Ss0OYOwHFjAJtkJfwyJ3rO5xwkurU-2fKedMZqCjVklVmY12uWqai1DRY1pNemfrQt9WRNMwRXKTqAQvU8x6aSiPF-1Vgn6Cso6CZlqGoU-9lmReyoFywET4O8DYwLTIYmmFYxyoevgpBo8TWJY8szNmTKSCdjujs7sghXf5umrGLCX3ZZJ0O2S-UZMXcUy0ECy3svmiWytPBhXeMd7NnKVQJtbaC2URGxb-Uv7tikh-FERiptupNyj1ALb_xJ5RVWnvJf7Rev9SBQc2glNSWGD1i-O-YclkYEpqyBTmk1WWQCpSCkZws9KEMYhmWT0VpLsBw14-WH7gxn0ogNbyQH-3pwcSuDjeuWxde_K0S89gOMy-M_vPUaVKWE_pAIPJHHptQ9T7FfSMYML9ZuCoqtStZOXEK7iHfA6-wrXjh8ipiP3CO-ueFsh1d4HgoUmcYeE4wh8hbCnQdpeYccqmlCuvwJBUS-6ZtUsWy5qaNk1iRtn0LM5TxmtZxFyPmukpmnXRUYDDyVIVGpG3oQdyQp3Ey65vzGIvqAGMY0OfiQYwuZKNtrt_lDiuQGXtNNc9SG8_UvkPCAfciN_djHKOlU8aw1wGwADOQaBYJYDju1e2cpcokKxeeYjnhQZXEW8bV9CAmq7ewL7eGuFIFIMRxvfjFzRuUYn7jNY1uYb4wL3SdkHFhLd4s6kRqAvhyWkquOG7sSg5VzzOGd8YO0WDW7tVBS-fxmoWeO8qNt6nhBHmyNYFAbTmBZLRNpipQ7UJGF25EuLqEL4GFxI2syfHFxYJTJZKaLAzd_UToFvNmcHzRlg7sFKXehChKt_HWANOVhfaTBJ2WF5XdOHzuZeLCdDpxE07yGFRxDqtGFcScXNAIjrDgdIRUKBClOl7sTu9ohtaGCttqWnhmn_QcnN_qOiApTwkKOPQSbfSGXQFKW3bNhkSp7z0gnztYR0Men2hBN3kMiCVM59kph1bsQj_C_TXgMrlCfsiwlaRQZP_c0kEJYEjfVIoKIJO4739B_sD8flC0uoXn-ci8GzAPeW2mFntsG7_OJsn3OWYRFcCFiI1k9S6MtmrrIzQSQQO9lNA",
    key_ops: [],
  };
  const pk = await suite.kem.importKey("jwk", jwkPub, true);
  // In addition to importing keys from external sources, you can also generate keys as follows:
  //   const rkp = await suite.kem.generateKeyPair();
  //   const rkp = await suite.kem.deriveKeyPair(random32bytesValue);

  const sender = await suite.createSenderContext({ recipientPublicKey: pk });

  const jwkPriv = {
    kty: "AKP",
    kid: "01",
    alg: "X-Wing",
    priv: "f5wrpOiPgn1hYEVQdgWFPtc7gJP277yI6xpurPpm7yY",
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

`@hpke/hybridkem-x-wing` needs to be used with
[@hpke/core](https://github.com/dajiaji/hpke-js/blob/main/packages/core/README.md),
which can be installed in the same manner as desribed below.

### Node.js

You can install the package with npm, yarn or pnpm.

```sh
# Using npm:
npm install @hpke/hybridkem-x-wing
yarn add @hpke/hybridkem-x-wing
pnpm install @hpke/hybridkem-x-wing
# Using jsr:
npx jsr add @hpke/hybridkem-x-wing
yarn dlx jsr add @hpke/hybridkem-x-wing
pnpm dlx jsr add @@hpke/hybridkem-x-wing
```

The above manner can be used with other JavaScript runtimes that support npm,
such as Cloudflare Workers and Bun.

Then, you can use the module from code like this:

```ts
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";
```

### Deno

For Deno, it is recommended to use the jsr.io registry.

```sh
deno add jsr:@hpke/hybridkem-x-wing
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
  import { XWing } from "https://esm.sh/@hpke/hybridkem-x-wing@<SEMVER>";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import {
    Aes256Gcm,
    CipherSuite,
    HkdfSha256,
  } from "https://esm.sh/@hpke/core";
  import { XWing } from "https://esm.sh/@hpke/hybridkem-x-wing";
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
  import { XWing } from "https://unpkg.com/@hpke/hybridkem-x-wing@<SEMVER>/esm/mod.js";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { XWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new XWing(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // Note that the `ct` (ciphertext) resulting from X-Wing Encapsulate() is set to `sender.enc`.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const encrypted = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc, // == `ct` (ciphertext) in the context of X-Wing
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
import { XWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new XWing(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // Note that the `ct` (ciphertext) resulting from X-Wing::Encapsulate() is set to `sender.enc`.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // encrypt
  const encrypted = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc, // == `ct` (ciphertext) in the context of X-Wing
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
      import { XWing } from "https://esm.sh/@hpke/hybridkem-x-wing";

      globalThis.doHpke = async () => {
        try {
          const suite = new CipherSuite({
            kem: new XWing(),
            kdf: new HkdfSha256(),
            aead: new Aes256Gcm(),
          });

          const rkp = await suite.kem.generateKeyPair();

          // Note that the `ct` resulting from X-Wing::Encapsulate() is set to `sender.enc`.
          const sender = await suite.createSenderContext({
            recipientPublicKey: rkp.publicKey,
          });
          // encrypt
          const encrypted = await sender.seal(
            new TextEncoder().encode("Hello world!"),
          );

          const recipient = await suite.createRecipientContext({
            recipientKey: rkp.privateKey, // rkp (CryptoKeyPair) is also acceptable.
            enc: sender.enc, // == `ct` (ciphertext) in the context of X-Wing
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
