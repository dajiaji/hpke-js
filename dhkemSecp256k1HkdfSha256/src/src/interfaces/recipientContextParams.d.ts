import type { KeyScheduleParams } from "./keyScheduleParams.js";
/**
 * The parameters used to setup the `RecipientContext`.
 */
export interface RecipientContextParams extends KeyScheduleParams {
    /** A recipient private key or a key pair. */
    recipientKey: CryptoKey | CryptoKeyPair;
    /** A byte string of the encapsulated key received from a sender. */
    enc: ArrayBuffer;
    /** A sender public key for Auth mode. */
    senderPublicKey?: CryptoKey;
}
