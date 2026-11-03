import { type AeadInterface, CipherSuite, HkdfSha512 } from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

import { CoseHpkeAlg } from "./alg.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 — Integrated Encryption. */
export function createHpke6(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Chacha20Poly1305(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_6);
}

/**
 * DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 — Key Encryption.
 *
 * @param contentAead The AEAD for content encryption (Layer 0), e.g.
 *   `new Aes128Gcm()`, `new Aes256Gcm()` or `new Chacha20Poly1305()`.
 *   The COSE content algorithm is derived from it.
 * @throws {CoseError} if contentAead has no COSE content-encryption equivalent.
 */
export function createHpke6Ke(contentAead: AeadInterface): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Chacha20Poly1305(),
  });
  return new CoseEncryptImpl(suite, CoseHpkeAlg.HPKE_6_KE, contentAead);
}
