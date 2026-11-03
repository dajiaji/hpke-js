import {
  type AeadInterface,
  Aes256Gcm,
  CipherSuite,
  DhkemP384HkdfSha384,
  HkdfSha384,
} from "@hpke/core";

import { CoseHpkeAlg } from "./alg.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-384), HKDF-SHA384, AES-256-GCM — Integrated Encryption. */
export function createHpke1(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP384HkdfSha384(),
    kdf: new HkdfSha384(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_1);
}

/**
 * DHKEM(P-384), HKDF-SHA384, AES-256-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()`, `new Aes256Gcm()` or `new Chacha20Poly1305()`.
 *   The COSE content algorithm is derived from it.
 * @throws {CoseError} if contentAead has no COSE content-encryption equivalent.
 */
export function createHpke1Ke(contentAead: AeadInterface): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP384HkdfSha384(),
    kdf: new HkdfSha384(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_1_KE, contentAead);
}
