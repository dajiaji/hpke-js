import type { AeadEncryptionContext } from "./aeadEncryptionContext.ts";

export interface KeyInfo {
  key: AeadEncryptionContext;
  baseNonce: Uint8Array;
  seq: number;
}
