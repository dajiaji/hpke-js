import type { KeyScheduleParams } from "./keyScheduleParams.ts";

/**
 * The parameters used to setup the `SenderContext`.
 */
export interface SenderContextParams extends KeyScheduleParams {
  /** A recipient public key. */
  recipientPublicKey: CryptoKey;

  /** A sender private key or a key pair for Auth mode. */
  senderKey?: CryptoKey | CryptoKeyPair;

  /** DO NOT USE. FOR DEBUGGING/TESTING PURPOSES ONLY. */
  ekm?: CryptoKeyPair | ArrayBuffer;
}
