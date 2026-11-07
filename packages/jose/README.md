# @hpke/jose

A TypeScript implementation of
[JOSE-HPKE](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
encryption based on [@hpke/core](https://github.com/dajiaji/hpke-js).

## Features

- **JWE Integrated Encryption** — direct HPKE encryption for single-recipient
  JWE.
- **JWE Key Encryption** — HPKE key wrapping with standard JWE content
  encryption (A128GCM, A256GCM) for multi-recipient JWE.
- `seal()` produces the Compact Serialization for Integrated Encryption and the
  General JSON Serialization for Key Encryption. `open()` accepts the Compact,
  Flattened JSON and General JSON Serializations for both.
- PSK mode. The `psk_id` header parameter carries `BASE64URL(id)`.

## Supported Environments

This package is distributed as ESM only. On Node.js, version 20 or later is
required.

## Supported Algorithms

Implements
[draft-ietf-jose-hpke-encrypt-22](https://datatracker.ietf.org/doc/html/draft-ietf-jose-hpke-encrypt-22).

| Integrated | Key Encryption | KEM                        | KDF         | AEAD             |
| ---------- | -------------- | -------------------------- | ----------- | ---------------- |
| HPKE-0     | HPKE-0-KE      | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1     | HPKE-1-KE      | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2     | HPKE-2-KE      | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3     | HPKE-3-KE      | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4     | -              | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5     | HPKE-5-KE      | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6     | -              | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7     | HPKE-7-KE      | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |

## Usage

### Integrated Encryption (Compact JWE)

```typescript
import { createJoseHpke3 } from "@hpke/jose";

const enc0 = createJoseHpke3();
const rkp = await enc0.generateKemKeyPair();

const plaintext = new TextEncoder().encode("Hello, JOSE-HPKE!");
const jwe = await enc0.seal(rkp.publicKey, plaintext);

const pt = await enc0.open(rkp, jwe);
// pt === plaintext
```

### Key Encryption (JSON JWE) with A128GCM

```typescript
import { Aes128Gcm, createJoseHpke3Ke } from "@hpke/jose";

const enc = createJoseHpke3Ke(new Aes128Gcm());
const rkp = await enc.generateKemKeyPair();

const plaintext = new TextEncoder().encode("Hello, JOSE-HPKE KE!");
const jwe = await enc.seal(
  [{ recipientPublicKey: rkp.publicKey }],
  plaintext,
);

const pt = await enc.open(rkp, jwe);
// pt === plaintext
```

The factory selects the HPKE suite for key wrapping; its AEAD argument selects
content encryption independently. This example uses AES-128-GCM for key wrapping
and AES-256-GCM for content encryption:

```typescript
import { Aes256Gcm, createJoseHpke3Ke } from "@hpke/jose";

const enc = createJoseHpke3Ke(new Aes256Gcm());
```

Supported content AEADs are `Aes128Gcm` and `Aes256Gcm`; other AEADs are
rejected when constructing the instance.

### Key Encryption with Multiple Recipients

```typescript
import { Aes128Gcm, createJoseHpke3Ke } from "@hpke/jose";

const enc = createJoseHpke3Ke(new Aes128Gcm());
const rkp1 = await enc.generateKemKeyPair();
const rkp2 = await enc.generateKemKeyPair();

const plaintext = new TextEncoder().encode("Multi-recipient!");
const jwe = await enc.seal(
  [
    { recipientPublicKey: rkp1.publicKey },
    { recipientPublicKey: rkp2.publicKey },
  ],
  plaintext,
);

// Both recipients can decrypt
const pt1 = await enc.open(rkp1, jwe);
const pt2 = await enc.open(rkp2, jwe);
```

## License

MIT
