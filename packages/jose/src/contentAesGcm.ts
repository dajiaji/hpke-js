/** Convert Uint8Array to ArrayBuffer (handles subarrays). */
function ab(u: Uint8Array): ArrayBuffer {
  return (u.buffer as ArrayBuffer).slice(
    u.byteOffset,
    u.byteOffset + u.byteLength,
  );
}

/**
 * Content encryption interface for Layer 0 (Key Encryption mode).
 * Returns ciphertext || tag combined.
 */
export interface ContentCrypto {
  seal(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array>;
  open(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    aad: Uint8Array,
  ): Promise<Uint8Array>;
}

export const aesGcmContentCrypto: ContentCrypto = {
  async seal(key, nonce, plaintext, aad) {
    const s = globalThis.crypto.subtle;
    const k = await s.importKey("raw", ab(key), "AES-GCM", false, [
      "encrypt",
    ]);
    return new Uint8Array(
      await s.encrypt(
        {
          name: "AES-GCM",
          iv: ab(nonce),
          additionalData: ab(aad),
          tagLength: 128,
        },
        k,
        ab(plaintext),
      ),
    );
  },
  async open(key, nonce, ciphertext, aad) {
    const s = globalThis.crypto.subtle;
    const k = await s.importKey("raw", ab(key), "AES-GCM", false, [
      "decrypt",
    ]);
    return new Uint8Array(
      await s.decrypt(
        {
          name: "AES-GCM",
          iv: ab(nonce),
          additionalData: ab(aad),
          tagLength: 128,
        },
        k,
        ab(ciphertext),
      ),
    );
  },
};
