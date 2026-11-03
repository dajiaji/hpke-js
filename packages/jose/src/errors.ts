/** Base error for @hpke/jose operations. */
export class JoseError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "JoseError";
  }
}

/** Wrap a failed crypto operation, retaining its original error as cause. */
export async function withJoseError<T>(
  message: string,
  fn: () => Promise<T>,
): Promise<T> {
  try {
    return await fn();
  } catch (e: unknown) {
    if (e instanceof JoseError) throw e;
    throw new JoseError(message, { cause: e });
  }
}
