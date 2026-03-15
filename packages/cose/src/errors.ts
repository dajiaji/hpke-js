/** Base error for @hpke/cose operations. */
export class CoseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "CoseError";
  }
}
