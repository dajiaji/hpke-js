import { CipherSuite, HkdfSha512 } from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

import { ContentAlg, CoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { type ContentCrypto, CoseEncryptImpl } from "./encrypt.ts";

const chacha20ContentCrypto: ContentCrypto = {
  async seal(key, nonce, plaintext, aad) {
    const chacha = new Chacha20Poly1305();
    const ctx = chacha.createEncryptionContext(key);
    return new Uint8Array(await ctx.seal(nonce, plaintext, aad));
  },
  async open(key, nonce, ciphertext, aad) {
    const chacha = new Chacha20Poly1305();
    const ctx = chacha.createEncryptionContext(key);
    return new Uint8Array(await ctx.open(nonce, ciphertext, aad));
  },
};

/** DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 — Integrated Encryption. */
export function createHpke6(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Chacha20Poly1305(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_6);
}

/** DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 — Key Encryption. */
export function createHpke6Ke(contentAlg: ContentAlg): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Chacha20Poly1305(),
  });
  const cc = contentAlg === ContentAlg.CHACHA20POLY1305
    ? chacha20ContentCrypto
    : aesGcmContentCrypto;
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_6_KE, contentAlg, cc);
}
