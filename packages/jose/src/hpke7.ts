import {
  type AeadInterface,
  Aes256Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { JoseHpkeAlg } from "./alg.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-256), HKDF-SHA256, AES-256-GCM — Integrated Encryption. */
export function createJoseHpke7(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_7);
}

/**
 * DHKEM(P-256), HKDF-SHA256, AES-256-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()` or `new Aes256Gcm()`.
 *   The JWE content algorithm is derived from it.
 * @throws {JoseError} if contentAead has no supported JWE content-encryption
 *   equivalent.
 */
export function createJoseHpke7Ke(contentAead: AeadInterface): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_7_KE,
    contentAead,
  );
}
