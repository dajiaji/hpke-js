/**
 * The base error class of hpke-js.
 */
class HpkeError extends Error {
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
    if (this.message === "") {
      this.message = this.name;
    } else {
      this.message = this.name + ": " + this.message;
    }
  }
}

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
 * Context AEAD seal() failure.
 */
export class SealError extends HpkeError {}

/**
 * Context AEAD open() failure.
 */
export class OpenError extends HpkeError {}

/**
 * Context AEAD sequence number overflow.
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
