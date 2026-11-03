import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

import { JoseHpkeAlg } from "./alg.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";

/** DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305 — Integrated Encryption. */
export function createJoseHpke4(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_4);
}
