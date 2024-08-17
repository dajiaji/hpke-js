// workaround for dnt.
// It's the samme as core/mod.ts and a temporary solution until dnt supports.
export type { AeadEncryptionContext } from "./core/src/interfaces/aeadEncryptionContext.ts";
export type { AeadInterface } from "./core/src/interfaces/aeadInterface.ts";
export type { CipherSuiteParams } from "./core/src/interfaces/cipherSuiteParams.ts";
export type { DhkemInterface } from "./core/src/interfaces/dhkemInterface.ts";
export type { DhkemPrimitives } from "./core/src/interfaces/dhkemPrimitives.ts";
export type {
  EncryptionContext,
  RecipientContext,
  SenderContext,
} from "./core/src/interfaces/encryptionContext.ts";
export type { KdfInterface } from "./core/src/interfaces/kdfInterface.ts";
export type { KemInterface } from "./core/src/interfaces/kemInterface.ts";
export type { PreSharedKey } from "./core/src/interfaces/preSharedKey.ts";
export type { RecipientContextParams } from "./core/src/interfaces/recipientContextParams.ts";
export type { CipherSuiteSealResponse } from "./core/src/interfaces/responses.ts";
export type { SenderContextParams } from "./core/src/interfaces/senderContextParams.ts";

export {
  KEM_USAGES,
  LABEL_DKP_PRK,
  LABEL_SK,
} from "./core/src/interfaces/dhkemPrimitives.ts";
export { SUITE_ID_HEADER_KEM } from "./core/src/interfaces/kemInterface.ts";

export { Aes128Gcm, Aes256Gcm } from "./core/src/aeads/aesGcm.ts";
export { ExportOnly } from "./core/src/aeads/exportOnly.ts";
export {
  HkdfSha256Native,
  HkdfSha384Native,
  HkdfSha512Native,
} from "./core/src/kdfs/hkdf.ts";
export { Dhkem } from "./core/src/kems/dhkem.ts";
export { Ec } from "./core/src/kems/dhkemPrimitives/ec.ts";
export { Hybridkem } from "./core/src/kems/hybridkem.ts";
export {
  base64UrlToBytes,
  concat,
  i2Osp,
  isCryptoKeyPair,
} from "./core/src/utils/misc.ts";

export { INPUT_LENGTH_LIMIT } from "./core/src/consts.ts";
export * from "./core/src/errors.ts";
export { AeadId, KdfId, KemId } from "./core/src/identifiers.ts";
export {
  CipherSuite,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  DhkemP521HkdfSha512,
  HkdfSha256,
  HkdfSha384,
  HkdfSha512,
} from "./core/src/native.ts";
export { XCryptoKey } from "./core/src/xCryptoKey.ts";
