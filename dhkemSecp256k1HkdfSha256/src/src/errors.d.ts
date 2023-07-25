/**
 * The base error class of hpke-js.
 */
declare class HpkeError extends Error {
    constructor(e: unknown);
}
/**
 * Invalid parameter.
 */
export declare class InvalidParamError extends HpkeError {
}
/**
 * KEM input or output validation failure.
 */
export declare class ValidationError extends HpkeError {
}
/**
 * Public or private key serialization failure.
 */
export declare class SerializeError extends HpkeError {
}
/**
 * Public or private key deserialization failure.
 */
export declare class DeserializeError extends HpkeError {
}
/**
 * encap() failure.
 */
export declare class EncapError extends HpkeError {
}
/**
 * decap() failure.
 */
export declare class DecapError extends HpkeError {
}
/**
 * Secret export failure.
 */
export declare class ExportError extends HpkeError {
}
/**
 * Context AEAD seal() failure.
 */
export declare class SealError extends HpkeError {
}
/**
 * Context AEAD open() failure.
 */
export declare class OpenError extends HpkeError {
}
/**
 * Context AEAD sequence number overflow.
 */
export declare class MessageLimitReachedError extends HpkeError {
}
/**
 * Key pair derivation failure.
 */
export declare class DeriveKeyPairError extends HpkeError {
}
/**
 * Not supported failure.
 */
export declare class NotSupportedError extends HpkeError {
}
export {};
