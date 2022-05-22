/**
 * The exporter interface.
 */
export interface Exporter {

  /**
   * Exports a secret using a variable-length pseudorandom function.
   *
   * @param exporterContext An exporter context string as bytes. The maximum length is 128 bytes.
   * @param len A desired length in bytes of the output secret.
   * @returns A secret string as bytes.
   * @throws {@link ExportError}
   */
  export(exporterContext: ArrayBuffer, len: number): Promise<ArrayBuffer>;
}
