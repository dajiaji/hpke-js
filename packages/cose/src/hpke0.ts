import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { type ContentAlg, CoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(P-256), HKDF-SHA256, AES-128-GCM — Integrated Encryption. */
export function createHpke0(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_0);
}

/** DHKEM(P-256), HKDF-SHA256, AES-128-GCM — Key Encryption. */
export function createHpke0Ke(contentAlg: ContentAlg): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new CoseEncryptImpl(
    suite,
    CoseHpkeAlg.HPKE_0_KE,
    contentAlg,
    aesGcmContentCrypto,
  );
}
