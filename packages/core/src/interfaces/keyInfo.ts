import type { AeadEncryptionContext } from "@hpke/common";

export interface KeyInfo {
  key: AeadEncryptionContext;
  baseNonce: Uint8Array;
  seq: number;
}
