/** Base error for @hpke/jose operations. */
export class JoseError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "JoseError";
  }
}
