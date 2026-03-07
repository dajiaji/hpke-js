/**
 * The pre-shared key interface.
 */
export interface PreSharedKey {
  /** The key identifier. */
  id: ArrayBufferLike | ArrayBufferView;

  /** The body of the pre-shared key. */
  key: ArrayBufferLike | ArrayBufferView;
}
