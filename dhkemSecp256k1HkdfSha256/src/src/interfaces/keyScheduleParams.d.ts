import type { PreSharedKey } from "./preSharedKey.js";
/**
 * The common parameters used to setup the `EncryptionContext`.
 */
export interface KeyScheduleParams {
    /** Application supplied information. The maximum length is 128 bytes. */
    info?: ArrayBuffer;
    /**
     * A pre-shared key (PSK) held by both the sender and recipient.
     * The PSK should have at least 32 bytes :and the maxmum length of the PSK is 128 bytes.
     */
    psk?: PreSharedKey;
}
