import { CipherSuite, HkdfSha512 } from "@hpke/core";
import { DhkemX448HkdfSha512 } from "@hpke/dhkem-x448";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

import { JoseHpkeAlg } from "./alg.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";

/** DHKEM(X448), HKDF-SHA512, ChaCha20Poly1305 — Integrated Encryption. */
export function createHpke6(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX448HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Chacha20Poly1305(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_6);
}
