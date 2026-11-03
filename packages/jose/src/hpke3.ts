import {
  type AeadInterface,
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { JoseHpkeAlg } from "./alg.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(X25519), HKDF-SHA256, AES-128-GCM — Integrated Encryption. */
export function createJoseHpke3(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_3);
}

/**
 * DHKEM(X25519), HKDF-SHA256, AES-128-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()` or `new Aes256Gcm()`.
 *   The JWE content algorithm is derived from it.
 * @throws {JoseError} if contentAead has no supported JWE content-encryption
 *   equivalent.
 */
export function createJoseHpke3Ke(contentAead: AeadInterface): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_3_KE,
    contentAead,
  );
}
