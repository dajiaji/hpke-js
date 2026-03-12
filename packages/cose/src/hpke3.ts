import {
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { type ContentAlg, CoseHpkeAlg } from "./alg.ts";
import { aesGcmContentCrypto } from "./contentAesGcm.ts";
import type { CoseEncrypt0 } from "./encrypt0.ts";
import { CoseEncrypt0Impl } from "./encrypt0.ts";
import type { CoseEncrypt } from "./encrypt.ts";
import { CoseEncryptImpl } from "./encrypt.ts";

/** DHKEM(X25519), HKDF-SHA256, AES-128-GCM — Integrated Encryption. */
export function createHpke3(): CoseEncrypt0 {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new CoseEncrypt0Impl(suite, CoseHpkeAlg.HPKE_3);
}

/** DHKEM(X25519), HKDF-SHA256, AES-128-GCM — Key Encryption. */
export function createHpke3Ke(contentAlg: ContentAlg): CoseEncrypt {
  const suite = new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
  return new CoseEncryptImpl(
    suite,
    CoseHpkeAlg.HPKE_3_KE,
    contentAlg,
    aesGcmContentCrypto,
  );
}
