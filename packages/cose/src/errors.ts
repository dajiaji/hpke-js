/** Base error for @hpke/cose operations. */
export class CoseError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CoseError";
  }
}

/**
 * Run an operation that calls into HPKE, an AEAD or WebCrypto, and report
 * any failure as a CoseError (the original error is kept as `cause`).
 * CoseErrors raised by this package pass through unchanged.
 */
export async function withCoseError<T>(
  message: string,
  fn: () => Promise<T>,
): Promise<T> {
  try {
    return await fn();
  } catch (e: unknown) {
    if (e instanceof CoseError) {
      throw e;
    }
    throw new CoseError(message, { cause: e });
  }
}
