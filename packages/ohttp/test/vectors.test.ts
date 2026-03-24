import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { BHttpDecoder } from "@dajiaji/bhttp";

import {
  Aes128Gcm,
  CipherSuite,
  DhkemX25519HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { buildHeader } from "../src/encapsulation.ts";
import { deserializeKeyConfig, serializeKeyConfig } from "../src/keyConfig.ts";

// RFC 9458 Appendix A test vectors
const VECTORS = {
  // Server (Gateway) secret key
  skR: "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a",
  // Key configuration (application/ohttp-keys)
  keyConfig:
    "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003",
  // Binary HTTP request (GET https://example.com/)
  binaryRequest: "00034745540568747470730b6578616d706c652e636f6d012f",
  // Ephemeral secret key used by the client
  skE: "bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73",
  // Encapsulated request
  encapsulatedRequest:
    "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525",
  // Binary HTTP response (200 OK with content)
  binaryResponse: "0140c8",
  // Exported secret from HPKE context
  exportedSecret: "62d87a6ba569ee81014c2641f52bea36",
  // Response nonce
  responseNonce: "c789e7151fcba46158ca84b04464910d",
  // AEAD key for response
  aeadKey: "5d0172a080e428b16d298c4ea0db620d",
  // AEAD nonce for response
  aeadNonce: "f6bf1aeb88d6df87007fa263",
  // Encapsulated response
  encapsulatedResponse:
    "c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd",
};

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Prepend a 2-byte length prefix to a raw KeyConfig to form application/ohttp-keys. */
function addLengthPrefix(raw: Uint8Array): Uint8Array {
  const buf = new Uint8Array(2 + raw.length);
  new DataView(buf.buffer).setUint16(0, raw.length);
  buf.set(raw, 2);
  return buf;
}

describe("RFC 9458 Appendix A test vectors", () => {
  it("should parse the key configuration correctly", () => {
    const keyConfigRaw = hexToBytes(VECTORS.keyConfig);
    const configs = deserializeKeyConfig(addLengthPrefix(keyConfigRaw));

    assertEquals(configs.length, 1);
    assertEquals(configs[0].keyId, 0x01);
    assertEquals(configs[0].kem, 0x0020); // X25519
    assertEquals(configs[0].publicKey.length, 32);
    assertEquals(configs[0].cipherSuites.length, 2);
    assertEquals(configs[0].cipherSuites[0].kdf, 0x0001); // HKDF-SHA256
    assertEquals(configs[0].cipherSuites[0].aead, 0x0001); // AES-128-GCM
    assertEquals(configs[0].cipherSuites[1].kdf, 0x0001);
    assertEquals(configs[0].cipherSuites[1].aead, 0x0003); // ChaCha20Poly1305
  });

  it("should re-serialize the key configuration to the same bytes", () => {
    const keyConfigRaw = hexToBytes(VECTORS.keyConfig);
    const withPrefix = addLengthPrefix(keyConfigRaw);
    const configs = deserializeKeyConfig(withPrefix);
    const reserialized = serializeKeyConfig(configs[0]);
    assertEquals(bytesToHex(reserialized), bytesToHex(withPrefix));
  });

  it("should correctly decode the binary HTTP request", () => {
    const binaryRequest = hexToBytes(VECTORS.binaryRequest);
    const decoder = new BHttpDecoder();
    const request = decoder.decodeRequest(binaryRequest);
    assertEquals(request.method, "GET");
    assertEquals(new URL(request.url).hostname, "example.com");
    assertEquals(new URL(request.url).pathname, "/");
  });

  it("should build the correct HPKE info for the encapsulated request header", () => {
    // hdr = keyId(1) || kemId(2) || kdfId(2) || aeadId(2) = 7 bytes
    const hdr = buildHeader(0x01, 0x0020, 0x0001, 0x0001);
    assertEquals(bytesToHex(hdr), "01002000010001");
  });

  it("should decrypt the encapsulated request with the server's private key", async () => {
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });

    const skR = await suite.kem.importKey(
      "raw",
      hexToBytes(VECTORS.skR).buffer as ArrayBuffer,
      false,
    );

    const encRequest = hexToBytes(VECTORS.encapsulatedRequest);

    // Parse the encapsulated request
    const view = new DataView(
      encRequest.buffer,
      encRequest.byteOffset,
      encRequest.byteLength,
    );
    const keyId = encRequest[0];
    const kemId = view.getUint16(1);
    const kdfId = view.getUint16(3);
    const aeadId = view.getUint16(5);

    assertEquals(keyId, 0x01);
    assertEquals(kemId, 0x0020);
    assertEquals(kdfId, 0x0001);
    assertEquals(aeadId, 0x0001);

    const nenc = 32; // X25519 enc size
    const hdrLen = 7;
    const enc = encRequest.slice(hdrLen, hdrLen + nenc);
    const ct = encRequest.slice(hdrLen + nenc);

    // Build info = "message/bhttp request" || 0x00 || hdr
    const label = new TextEncoder().encode("message/bhttp request");
    const hdr = buildHeader(keyId, kemId, kdfId, aeadId);
    const info = new Uint8Array(label.length + 1 + hdr.length);
    info.set(label, 0);
    info[label.length] = 0;
    info.set(hdr, label.length + 1);

    const rctx = await suite.createRecipientContext({
      recipientKey: skR,
      enc,
      info: info.buffer as ArrayBuffer,
    });

    const plaintext = new Uint8Array(
      await rctx.open(ct, new Uint8Array(0)),
    );

    // The decrypted plaintext should match the binary HTTP request
    assertEquals(bytesToHex(plaintext), VECTORS.binaryRequest);

    // Verify we can decode it as a valid HTTP request
    const decoder = new BHttpDecoder();
    const request = decoder.decodeRequest(plaintext);
    assertEquals(request.method, "GET");
  });

  it("should derive the correct response key and nonce", async () => {
    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });

    const skR = await suite.kem.importKey(
      "raw",
      hexToBytes(VECTORS.skR).buffer as ArrayBuffer,
      false,
    );

    const encRequest = hexToBytes(VECTORS.encapsulatedRequest);
    const hdrLen = 7;
    const nenc = 32;
    const enc = encRequest.slice(hdrLen, hdrLen + nenc);
    const ct = encRequest.slice(hdrLen + nenc);

    const label = new TextEncoder().encode("message/bhttp request");
    const hdr = buildHeader(0x01, 0x0020, 0x0001, 0x0001);
    const info = new Uint8Array(label.length + 1 + hdr.length);
    info.set(label, 0);
    info[label.length] = 0;
    info.set(hdr, label.length + 1);

    const rctx = await suite.createRecipientContext({
      recipientKey: skR,
      enc,
      info: info.buffer as ArrayBuffer,
    });
    await rctx.open(ct, new Uint8Array(0));

    // Export secret for response
    const responseLabel = new TextEncoder().encode("message/bhttp response");
    const nn = suite.aead.nonceSize; // 12
    const nk = suite.aead.keySize; // 16
    const secretLen = Math.max(nn, nk); // 16

    const secret = new Uint8Array(
      await rctx.export(responseLabel.buffer as ArrayBuffer, secretLen),
    );
    assertEquals(bytesToHex(secret), VECTORS.exportedSecret);

    // Derive response key and nonce
    const responseNonce = hexToBytes(VECTORS.responseNonce);
    const salt = new Uint8Array(enc.length + responseNonce.length);
    salt.set(enc, 0);
    salt.set(responseNonce, enc.length);

    // HKDF-Extract(salt, secret) using raw HMAC (salt length != hashSize)
    const saltKey = await crypto.subtle.importKey(
      "raw",
      salt,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const prk = await crypto.subtle.sign(
      "HMAC",
      saltKey,
      secret.buffer as ArrayBuffer,
    );

    const labelKey = new TextEncoder().encode("key");
    const labelNonce = new TextEncoder().encode("nonce");
    const aeadKey = await suite.kdf.expand(prk, labelKey, nk);
    const aeadNonce = await suite.kdf.expand(prk, labelNonce, nn);

    assertEquals(bytesToHex(new Uint8Array(aeadKey)), VECTORS.aeadKey);
    assertEquals(bytesToHex(new Uint8Array(aeadNonce)), VECTORS.aeadNonce);

    // Decrypt the encapsulated response
    const encResponse = hexToBytes(VECTORS.encapsulatedResponse);
    const respNonce = encResponse.slice(0, secretLen);
    const respCt = encResponse.slice(secretLen);

    assertEquals(bytesToHex(respNonce), VECTORS.responseNonce);

    const aeadCtx = suite.aead.createEncryptionContext(aeadKey);
    const responsePlaintext = new Uint8Array(
      await aeadCtx.open(aeadNonce, respCt, new Uint8Array(0)),
    );
    assertEquals(bytesToHex(responsePlaintext), VECTORS.binaryResponse);
  });

  it("should decrypt the encapsulated response via OhttpServer + manual client decapsulation", async () => {
    // Use our high-level OhttpServer to decapsulate the request
    const { OhttpServer } = await import("../mod.ts");

    const suite = new CipherSuite({
      kem: new DhkemX25519HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });

    const skR = await suite.kem.importKey(
      "raw",
      hexToBytes(VECTORS.skR).buffer as ArrayBuffer,
      false,
    );
    const keyConfigRaw = hexToBytes(VECTORS.keyConfig);
    const configs = deserializeKeyConfig(addLengthPrefix(keyConfigRaw));
    const pkR = await suite.kem.importKey(
      "raw",
      configs[0].publicKey.buffer as ArrayBuffer,
      true,
    );

    const server = new OhttpServer({
      keyId: 0x01,
      kem: new DhkemX25519HkdfSha256(),
      privateKey: skR,
      publicKey: pkR,
      kdfAeadPairs: [
        { kdf: new HkdfSha256(), aead: new Aes128Gcm() },
      ],
    });

    const encRequest = hexToBytes(VECTORS.encapsulatedRequest);
    const serverCtx = await server.decapsulateRequest(encRequest);

    // Verify the decrypted request
    assertEquals(serverCtx.request.method, "GET");
    assertEquals(new URL(serverCtx.request.url).hostname, "example.com");
  });
});
