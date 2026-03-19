import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { type ContentEncAlg, JoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-256), HKDF-SHA256, AES-128-GCM — Integrated Encryption. */
export function createHpke0(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_0);
}

/** DHKEM(P-256), HKDF-SHA256, AES-128-GCM — Key Encryption. */
export function createHpke0Ke(contentEncAlg: ContentEncAlg): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_0_KE,
    contentEncAlg,
    aesGcmContentCrypto,
  );
}
