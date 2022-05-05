/**
 * The exporter interface.
 *
 * @public
 */
export interface Exporter {

  /**
   * Exports a secret using a variable-length pseudorandom function.
   */
  export(info: ArrayBuffer, len: number): Promise<ArrayBuffer>;
}
