/**
 * The base error class of hpke-js.
 */
export class BaseError extends Error {
  public constructor(e: unknown) {
    let message: string;

    if (e instanceof Error) {
      message = e.message;
    } else if (typeof e === "string") {
      message = e;
    } else {
      message = "";
    }
    super(message);

    this.name = this.constructor.name;
  }
}

/**
 * The base error class of hpke-js.
 */
export class HpkeError extends BaseError {}

/**
 * Invalid parameter.
 */
export class InvalidParamError extends HpkeError {}

/**
 * KEM input or output validation failure.
 */
export class ValidationError extends HpkeError {}

/**
 * Public or private key serialization failure.
 */
export class SerializeError extends HpkeError {}

/**
 * Public or private key deserialization failure.
 */
export class DeserializeError extends HpkeError {}

/**
 * encap() failure.
 */
export class EncapError extends HpkeError {}

/**
 * decap() failure.
 */
export class DecapError extends HpkeError {}

/**
 * Secret export failure.
 */
export class ExportError extends HpkeError {}

/**
 * seal() failure.
 */
export class SealError extends HpkeError {}

/**
 * open() failure.
 */
export class OpenError extends HpkeError {}

/**
 * Sequence number overflow on the encryption context.
 */
export class MessageLimitReachedError extends HpkeError {}

/**
 * Key pair derivation failure.
 */
export class DeriveKeyPairError extends HpkeError {}

/**
 * Not supported failure.
 */
export class NotSupportedError extends HpkeError {}
