import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
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

/** DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305 — Integrated Encryption. */
export function createHpke4(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_4);
}

/** DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305 — Key Encryption. */
export function createHpke4Ke(contentAlg: ContentAlg): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  const cc = contentAlg === ContentAlg.CHACHA20POLY1305
    ? chacha20ContentCrypto
    : aesGcmContentCrypto;
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_4_KE, contentAlg, cc);
}
