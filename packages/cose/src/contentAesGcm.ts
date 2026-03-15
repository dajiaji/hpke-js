import type { ContentCrypto } from "./encrypt.ts";

/** Convert Uint8Array → ArrayBuffer (handles subarrays). */
function ab(u: Uint8Array): ArrayBuffer {
  return (u.buffer as ArrayBuffer).slice(
    u.byteOffset,
    u.byteOffset + u.byteLength,
  );
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
