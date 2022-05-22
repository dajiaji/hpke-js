import type { PreSharedKey } from './preSharedKey';

/**
 * The common parameters used to setup the {@link EncryptionContext}
 */
export interface KeyScheduleParams {

  /** Application supplied information. The maximum length is 128 bytes. */
  info?: ArrayBuffer;

  /** A pre-shared key (PSK) held by both the sender and recipient. The maximum length is 128 bytes. */
  psk?: PreSharedKey;
}
