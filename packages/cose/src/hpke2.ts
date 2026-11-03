import {
  type AeadInterface,
  Aes256Gcm,
  CipherSuite,
  DhkemP521HkdfSha512,
  HkdfSha512,
} from "@hpke/core";

import { CoseHpkeAlg } from "./alg.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-521), HKDF-SHA512, AES-256-GCM — Integrated Encryption. */
export function createCoseHpke2(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP521HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_2);
}

/**
 * DHKEM(P-521), HKDF-SHA512, AES-256-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()`, `new Aes256Gcm()` or `new Chacha20Poly1305()`.
 *   The COSE content algorithm is derived from it.
 * @throws {CoseError} if contentAead has no COSE content-encryption equivalent.
 */
export function createCoseHpke2Ke(contentAead: AeadInterface): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP521HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_2_KE, contentAead);
}
