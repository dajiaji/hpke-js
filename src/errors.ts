class HpkeError extends Error {

  public constructor(e: unknown) {

    let message: string;

    if (e instanceof Error) {
      message = e.message;  
    } else if (typeof e === 'string') { 
      message = e;  
    } else {
      message = '';
    }
    super(message);

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = this.constructor.name;
    if (this.message === '') {
      this.message = this.name;
    } else {
      this.message = this.name + ': ' + this.message;
    }
  }
}

export class InvalidParamError extends HpkeError {}
export class ValidationError extends HpkeError {}
export class SerializeError extends HpkeError {}
export class DeserializeError extends HpkeError {}
export class EncapError extends HpkeError {}
export class DecapError extends HpkeError {}
export class ExportError extends HpkeError {}
export class SealError extends HpkeError {}
export class OpenError extends HpkeError {}
export class MessageLimitReachedError extends HpkeError {}
export class DeriveKeyPairError extends HpkeError {}
export class NotSupportedError extends HpkeError {}
