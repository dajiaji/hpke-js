import type { AeadKey } from './aeadKey';

export interface KeyInfo {
  key: AeadKey;
  baseNonce: Uint8Array;
  seq: number;
}
