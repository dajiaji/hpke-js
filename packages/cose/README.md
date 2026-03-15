# @hpke/cose

A TypeScript implementation of
[COSE-HPKE (draft-ietf-cose-hpke)](https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/)
built on top of
[@hpke/core](https://github.com/dajiaji/hpke-js/tree/main/packages/core).

## Features

- **COSE_Encrypt0** (Integrated Encryption) — single-recipient HPKE encryption
  directly into the COSE_Encrypt0 structure.
- **COSE_Encrypt** (Key Encryption) — multi-recipient HPKE key wrapping with a
  content encryption key.

## Supported Algorithms

| Name   | COSE Value | KEM                        | KDF         | AEAD             |
| ------ | ---------- | -------------------------- | ----------- | ---------------- |
| HPKE-0 | 35         | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1 | 37         | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2 | 39         | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3 | 41         | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4 | 42         | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5 | 43         | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6 | 44         | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7 | 45         | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |

Key Encryption variants (HPKE-0-KE through HPKE-7-KE) use COSE values 46–53.

## Usage

### COSE_Encrypt0 (Integrated Encryption)

```ts
import { createHpke3 } from "@hpke/cose";

const enc0 = createHpke3();
const rkp = await enc0.suite.kem.generateKeyPair();

const ct = await enc0.seal(rkp.publicKey, new TextEncoder().encode("hello"));
const pt = await enc0.open(rkp, ct);
// new TextDecoder().decode(pt) === "hello"
```

### COSE_Encrypt (Key Encryption)

```ts
import { ContentAlg, createHpke3Ke } from "@hpke/cose";

const enc = createHpke3Ke(ContentAlg.A128GCM);
const rkp = await enc.generateKemKeyPair();

const ct = await enc.seal(
  [{ recipientPublicKey: rkp.publicKey }],
  new TextEncoder().encode("hello"),
);
const pt = await enc.open(rkp, ct);
// new TextDecoder().decode(pt) === "hello"
```

## License

MIT
