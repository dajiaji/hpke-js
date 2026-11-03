import {
  type AeadInterface,
  Aes256Gcm,
  CipherSuite,
  DhkemP384HkdfSha384,
  HkdfSha384,
} from "@hpke/core";

import { JoseHpkeAlg } from "./alg.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-384), HKDF-SHA384, AES-256-GCM — Integrated Encryption. */
export function createJoseHpke1(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP384HkdfSha384(),
    kdf: new HkdfSha384(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_1);
}

/**
 * DHKEM(P-384), HKDF-SHA384, AES-256-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()` or `new Aes256Gcm()`.
 *   The JWE content algorithm is derived from it.
 * @throws {JoseError} if contentAead has no supported JWE content-encryption
 *   equivalent.
 */
export function createJoseHpke1Ke(contentAead: AeadInterface): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP384HkdfSha384(),
    kdf: new HkdfSha384(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_1_KE,
    contentAead,
  );
}
