import {
  Aes256Gcm,
  CipherSuite,
  DhkemP521HkdfSha512,
  HkdfSha512,
} from "@hpke/core";

import { type ContentEncAlg, JoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { JoseEncrypt0 } from "./encrypt0.ts";
import { JoseEncrypt0Impl } from "./encrypt0.ts";
import type { JoseEncrypt } from "./encrypt.ts";
import { JoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-521), HKDF-SHA512, AES-256-GCM — Integrated Encryption. */
export function createHpke2(): JoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP521HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncrypt0Impl(suite, JoseHpkeAlg.HPKE_2);
}

/** DHKEM(P-521), HKDF-SHA512, AES-256-GCM — Key Encryption. */
export function createHpke2Ke(contentEncAlg: ContentEncAlg): JoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP521HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new JoseEncryptImpl(
    suite,
    JoseHpkeAlg.HPKE_2_KE,
    contentEncAlg,
    aesGcmContentCrypto,
  );
}
