/**
 * The exporter interface.
 */
export interface Exporter {

  /**
   * Exports a secret using a variable-length pseudorandom function.
   *
   * @param info An exporter context string as bytes.
   * @param len A desired length in bytes of the output secret.
   * @returns A secret string as bytes.
   * @throws {@link ExportError}
   */
  export(info: ArrayBuffer, len: number): Promise<ArrayBuffer>;
}
