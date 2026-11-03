import {
  type AeadInterface,
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { CoseHpkeAlg } from "./alg.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(X25519), HKDF-SHA256, AES-128-GCM — Integrated Encryption. */
export function createCoseHpke3(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_3);
}

/**
 * DHKEM(X25519), HKDF-SHA256, AES-128-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()`, `new Aes256Gcm()` or `new Chacha20Poly1305()`.
 *   The COSE content algorithm is derived from it.
 * @throws {CoseError} if contentAead has no COSE content-encryption equivalent.
 */
export function createCoseHpke3Ke(contentAead: AeadInterface): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_3_KE, contentAead);
}
