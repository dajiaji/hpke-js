import {
  type AeadInterface,
  Aes256Gcm,
  CipherSuite,
  HkdfSha512,
} from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";

import { CoseHpkeAlg } from "./alg.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(X448), HKDF-SHA512, AES-256-GCM — Integrated Encryption. */
export function createCoseHpke5(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_5);
}

/**
 * DHKEM(X448), HKDF-SHA512, AES-256-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()`, `new Aes256Gcm()` or `new Chacha20Poly1305()`.
 *   The COSE content algorithm is derived from it.
 * @throws {CoseError} if contentAead has no COSE content-encryption equivalent.
 */
export function createCoseHpke5Ke(contentAead: AeadInterface): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_5_KE, contentAead);
}
