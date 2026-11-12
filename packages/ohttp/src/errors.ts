/** Base error for @hpke/ohttp operations. */
export class OhttpError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "OhttpError";
  }
}
