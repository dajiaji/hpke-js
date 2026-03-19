# @hpke/jose

A TypeScript implementation of
[JOSE-HPKE](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/)
encryption based on [@hpke/core](https://github.com/dajiaji/hpke-js).

## Features

- **JWE Integrated Encryption** (Compact Serialization) — direct HPKE encryption
  for single-recipient JWE.
- **JWE Key Encryption** (JSON Serialization) — HPKE key wrapping with standard
  JWE content encryption (A128GCM, A256GCM) for multi-recipient JWE.

## Supported Algorithms

| Algorithm | KEM                        | KDF         | AEAD             |
| --------- | -------------------------- | ----------- | ---------------- |
| HPKE-0    | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-128-GCM      |
| HPKE-1    | DHKEM(P-384, HKDF-SHA384)  | HKDF-SHA384 | AES-256-GCM      |
| HPKE-2    | DHKEM(P-521, HKDF-SHA512)  | HKDF-SHA512 | AES-256-GCM      |
| HPKE-3    | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | AES-128-GCM      |
| HPKE-4    | DHKEM(X25519, HKDF-SHA256) | HKDF-SHA256 | ChaCha20Poly1305 |
| HPKE-5    | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | AES-256-GCM      |
| HPKE-6    | DHKEM(X448, HKDF-SHA512)   | HKDF-SHA512 | ChaCha20Poly1305 |
| HPKE-7    | DHKEM(P-256, HKDF-SHA256)  | HKDF-SHA256 | AES-256-GCM      |

## Usage

### Integrated Encryption (Compact JWE)

```typescript
import { createHpke3 } from "@hpke/jose";

const enc0 = createHpke3();
const rkp = await enc0.suite.kem.generateKeyPair();

const plaintext = new TextEncoder().encode("Hello, JOSE-HPKE!");
const jwe = await enc0.seal(rkp.publicKey, plaintext);

const pt = await enc0.open(rkp, jwe);
// pt === plaintext
```

### Key Encryption (JSON JWE) with A128GCM

```typescript
import { ContentEncAlg, createHpke3Ke } from "@hpke/jose";

const enc = createHpke3Ke(ContentEncAlg.A128GCM);
const rkp = await enc.generateKemKeyPair();

const plaintext = new TextEncoder().encode("Hello, JOSE-HPKE KE!");
const jwe = await enc.seal(
  [{ recipientPublicKey: rkp.publicKey }],
  plaintext,
);

const pt = await enc.open(rkp, jwe);
// pt === plaintext
```

### Key Encryption with Multiple Recipients

```typescript
import { ContentEncAlg, createHpke3Ke } from "@hpke/jose";

const enc = createHpke3Ke(ContentEncAlg.A128GCM);
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
