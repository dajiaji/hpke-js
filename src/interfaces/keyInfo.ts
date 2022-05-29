import type { AeadKey } from "./aeadKey.ts";

export interface KeyInfo {
  key: AeadKey;
  baseNonce: Uint8Array;
  seq: number;
}
