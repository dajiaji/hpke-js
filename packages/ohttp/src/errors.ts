/** An OHTTP protocol failure; authentication failures retain the original cause. */
export class OhttpError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "OhttpError";
  }
}

/** Normalize authentication failures at the response AEAD boundary. */
export async function decryptResponse<T>(open: () => Promise<T>): Promise<T> {
  try {
    return await open();
  } catch (error) {
    if (
      error instanceof TypeError ||
      (error instanceof DOMException && error.name === "AbortError")
    ) throw error;
    throw new OhttpError("Response decryption failed", { cause: error });
  }
}
