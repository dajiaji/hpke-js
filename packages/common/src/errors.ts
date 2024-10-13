/**
 * The base error class of hpke-js.
 * @group Errors
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
 * @group Errors
 */
export class HpkeError extends BaseError {}

/**
 * Invalid parameter.
 * @group Errors
 */
export class InvalidParamError extends HpkeError {}

/**
 * KEM input or output validation failure.
 * @group Errors
 */
export class ValidationError extends HpkeError {}

/**
 * Public or private key serialization failure.
 * @group Errors
 */
export class SerializeError extends HpkeError {}

/**
 * Public or private key deserialization failure.
 * @group Errors
 */
export class DeserializeError extends HpkeError {}

/**
 * encap() failure.
 * @group Errors
 */
export class EncapError extends HpkeError {}

/**
 * decap() failure.
 * @group Errors
 */
export class DecapError extends HpkeError {}

/**
 * Secret export failure.
 * @group Errors
 */
export class ExportError extends HpkeError {}

/**
 * seal() failure.
 * @group Errors
 */
export class SealError extends HpkeError {}

/**
 * open() failure.
 * @group Errors
 */
export class OpenError extends HpkeError {}

/**
 * Sequence number overflow on the encryption context.
 * @group Errors
 */
export class MessageLimitReachedError extends HpkeError {}

/**
 * Key pair derivation failure.
 * @group Errors
 */
export class DeriveKeyPairError extends HpkeError {}

/**
 * Not supported failure.
 * @group Errors
 */
export class NotSupportedError extends HpkeError {}
