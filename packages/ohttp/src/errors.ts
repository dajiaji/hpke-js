export class OhttpError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "OhttpError";
  }
}
