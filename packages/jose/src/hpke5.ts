import {
  type AeadInterface,
  Aes256Gcm,
  CipherSuite,
  HkdfSha512,
} from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";

import { JoseHpkeAlg } from "./alg.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(X448), HKDF-SHA512, AES-256-GCM — Integrated Encryption. */
export function createJoseHpke5(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_5);
}

/**
 * DHKEM(X448), HKDF-SHA512, AES-256-GCM — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()` or `new Aes256Gcm()`.
 *   The JWE content algorithm is derived from it.
 * @throws {JoseError} if contentAead has no supported JWE content-encryption
 *   equivalent.
 */
export function createJoseHpke5Ke(contentAead: AeadInterface): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_5_KE,
    contentAead,
  );
}
