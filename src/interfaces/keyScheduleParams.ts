import type { PreSharedKey } from './preSharedKey';

/**
 * The common parameters used to setup the {@link EncryptionContext}
 */
export interface KeyScheduleParams {

  /** Application supplied information */
  info?: ArrayBuffer;

  /** A pre-shared key (PSK) held by both the sender and recipient */
  psk?: PreSharedKey;
}
