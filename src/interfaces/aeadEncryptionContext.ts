// The key usages for AEAD.
export const AEAD_USAGES: KeyUsage[] = ["encrypt", "decrypt"];

/**
 * The AEAD encryption context interface.
 */
export interface AeadEncryptionContext {
  /**
   * Encrypts data with an initialization vector and additional authenticated data.
   *
   * @param iv An initialization vector.
   * @param data A plain text as bytes to be encrypted.
   * @param aad Additional authenticated data as bytes fed by an application.
   * @returns A cipher text as bytes.
   */
  seal(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  /**
   * Decrypts data with an initialization vector and additional authenticated data.
   *
   * @param iv An initialization vector.
   * @param data A plain text as bytes to be encrypted.
   * @param aad Additional authenticated data as bytes fed by an application.
   * @returns A decrypted plain text as bytes.
   */
  open(
    iv: ArrayBuffer,
    data: ArrayBuffer,
    aad: ArrayBuffer,
  ): Promise<ArrayBuffer>;
}
