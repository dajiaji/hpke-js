import type { CipherSuite } from "@hpke/core";
import { OhttpError } from "./errors.ts";

const LABEL_KEY = new TextEncoder().encode("key");
const LABEL_NONCE = new TextEncoder().encode("nonce");

/**
 * Build the 7-byte header:
 *   keyId (1) || kemId (2) || kdfId (2) || aeadId (2)
 */
export function buildHeader(
  keyId: number,
  kemId: number,
  kdfId: number,
  aeadId: number,
): Uint8Array {
  const hdr = new Uint8Array(7);
  const view = new DataView(hdr.buffer);
  hdr[0] = keyId;
  view.setUint16(1, kemId);
  view.setUint16(3, kdfId);
  view.setUint16(5, aeadId);
  return hdr;
}

/**
 * Derive response AEAD key and nonce (RFC 9458 Section 4.4).
 *
 * salt = concat(enc, response_nonce)
 * prk  = Extract(salt, secret)
 * key  = Expand(prk, "key", Nk)
 * nonce = Expand(prk, "nonce", Nn)
 *
 * Uses raw HMAC for Extract because the salt length may exceed
 * the KDF's hashSize (which the HPKE KDF implementation rejects).
 */
export async function deriveResponseKeyNonce(
  suite: CipherSuite,
  enc: Uint8Array,
  responseNonce: Uint8Array,
  secret: Uint8Array,
): Promise<{ key: ArrayBuffer; nonce: ArrayBuffer }> {
  const salt = new Uint8Array(enc.length + responseNonce.length);
  salt.set(enc, 0);
  salt.set(responseNonce, enc.length);

  // HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)
  const hmacAlg = kdfHashAlgorithm(suite.kdf.id);
  const saltKey = await crypto.subtle.importKey(
    "raw",
    salt,
    { name: "HMAC", hash: hmacAlg },
    false,
    ["sign"],
  );
  const prk = await crypto.subtle.sign(
    "HMAC",
    saltKey,
    secret.buffer as ArrayBuffer,
  );

  const key = await suite.kdf.expand(prk, LABEL_KEY, suite.aead.keySize);
  const nonce = await suite.kdf.expand(
    prk,
    LABEL_NONCE,
    suite.aead.nonceSize,
  );

  return { key, nonce };
}

function kdfHashAlgorithm(kdfId: number): string {
  switch (kdfId) {
    case 0x0001:
      return "SHA-256";
    case 0x0002:
      return "SHA-384";
    case 0x0003:
      return "SHA-512";
    default:
      throw new OhttpError(`Unsupported KDF ID: 0x${kdfId.toString(16)}`);
  }
}
