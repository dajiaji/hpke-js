/**
 * The pre-shared key interface.
 */
export interface PreSharedKey {

  /** The key identifier. */
  id: ArrayBuffer;

  /** The body of the pre-shared key. */
  key: ArrayBuffer;
}
