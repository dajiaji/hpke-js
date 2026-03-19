import {
  Aes256Gcm,
  CipherSuite,
  DhkemP384HkdfSha384,
  HkdfSha384,
} from "@hpke/core";

import { type ContentEncAlg, JoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-384), HKDF-SHA384, AES-256-GCM — Integrated Encryption. */
export function createHpke1(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP384HkdfSha384(),
    kdf: new HkdfSha384(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_1);
}

/** DHKEM(P-384), HKDF-SHA384, AES-256-GCM — Key Encryption. */
export function createHpke1Ke(contentEncAlg: ContentEncAlg): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP384HkdfSha384(),
    kdf: new HkdfSha384(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_1_KE,
    contentEncAlg,
    aesGcmContentCrypto,
  );
}
