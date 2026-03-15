import {
  Aes256Gcm,
  CipherSuite,
  DhkemP521HkdfSha512,
  HkdfSha512,
} from "@hpke/core";

import { type ContentAlg, CoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-521), HKDF-SHA512, AES-256-GCM — Integrated Encryption. */
export function createHpke2(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP521HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_2);
}

/** DHKEM(P-521), HKDF-SHA512, AES-256-GCM — Key Encryption. */
export function createHpke2Ke(contentAlg: ContentAlg): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP521HkdfSha512(),
    kdf: new HkdfSha512(),
    aead: new Aes256Gcm(),
  });
  return new CoseEncryptImpl(
    suite,
    CoseHpkeAlg.HPKE_2_KE,
    contentAlg,
    aesGcmContentCrypto,
  );
}
