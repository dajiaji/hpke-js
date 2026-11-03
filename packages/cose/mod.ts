// Content encryption AEADs for the Key Encryption factories, re-exported so
// callers do not need a direct dependency on @hpke/core or
// @hpke/chacha20poly1305.
export type { AeadInterface } from "@hpke/core";
export { Aes128Gcm, Aes256Gcm } from "@hpke/core";
export { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

export { ContentAlg, CoseHpkeAlg } from "./src/alg.ts";
export type {
  CoseEncrypt0,
  CoseEncrypt0DetachedResult,
  CoseEncrypt0Options,
} from "./src/encrypt0.ts";
export type { CoseEncrypt } from "./src/encrypt.ts";
export type {
  CoseEncryptDetachedResult,
  CoseEncryptOpenOptions,
  CoseEncryptSealOptions,
  CoseRecipient,
} from "./src/encrypt.ts";
export { CoseError } from "./src/errors.ts";
export {
  buildEc2CoseKey,
  buildOkpCoseKey,
  CoseCrv,
  CoseKty,
  extractCurve,
  extractPrivateKeyBytes,
  extractPublicKeyBytes,
} from "./src/coseKey.ts";
export type { CoseKeyBuildOptions } from "./src/coseKey.ts";

export { createHpke0, createHpke0Ke } from "./src/hpke0.ts";
export { createHpke1, createHpke1Ke } from "./src/hpke1.ts";
export { createHpke2, createHpke2Ke } from "./src/hpke2.ts";
export { createHpke3, createHpke3Ke } from "./src/hpke3.ts";
export { createHpke4, createHpke4Ke } from "./src/hpke4.ts";
export { createHpke5, createHpke5Ke } from "./src/hpke5.ts";
export { createHpke6, createHpke6Ke } from "./src/hpke6.ts";
export { createHpke7, createHpke7Ke } from "./src/hpke7.ts";
