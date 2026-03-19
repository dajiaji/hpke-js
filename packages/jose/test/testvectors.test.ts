/**
 * Test vectors from draft-ietf-jose-hpke-encrypt-16.
 *
 * Keys: Appendix A.1 (Integrated) and A.2 (Key Encryption)
 * Examples: Sections 5.2, 5.3, and 6.3
 *
 * Plaintext (discovered by decryption):
 *   "You can trust us to stick with you through thick and thin\u2013to the
 *    bitter end. And you can trust us to keep any secret of yours\u2013closer
 *    than you keep it yourself. But you cannot trust us to let you face
 *    trouble alone, and go off without a word. We are your friends, Frodo."
 *
 * AAD (where applicable):
 *   "The Fellowship of the Ring"
 */
import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { createHpke0, createHpke0Ke } from "../mod.ts";

// --- Keys from Appendix A ---

/** Appendix A.1 — Integrated Encryption Key (P-256, HPKE-0) */
const jwkA1 = {
  kty: "EC",
  use: "enc",
  alg: "HPKE-0",
  kid: "yCnfbmYMZcWrKDt_DjNebRCB1vxVoqv4umJ4WK8RYjk",
  crv: "P-256",
  x: "gixQJ0qg4Ag-6HSMaIEDL_zbDhoXavMyKlmdn__AQVE",
  y: "ZxTgRLWaKONCL_GbZKLNPsW9EW6nBsN4AwQGEFAFFbM",
  d: "g2DXtKapi2oN2zL_RCWX8D4bWURHCKN2-ZNGC05ZaR8",
};

/** Appendix A.2 — Key Encryption Key (P-256, HPKE-0-KE) */
const jwkA2 = {
  kty: "EC",
  use: "enc",
  alg: "HPKE-0-KE",
  kid: "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
  crv: "P-256",
  x: "WVKOswXQAgntIrLSYlwkyaU1dIE-FIhrbTEotFgMwIA",
  y: "jpZT1WNmQH752Bh_pDK41IhLkiXLj-15wR4ZBZ-MWFk",
  d: "MeCnMF65SaRVZ11Gf1Weacx3H9SdzO7MtWcDXvHWNv8",
};

// --- Expected plaintext (same for all 3 examples) ---
const EXPECTED_PLAINTEXT =
  "You can trust us to stick with you through thick and thin\u2013to the bitter end. " +
  "And you can trust us to keep any secret of yours\u2013closer than you keep it yourself. " +
  "But you cannot trust us to let you face trouble alone, and go off without a word. " +
  "We are your friends, Frodo.";

// --- Helpers ---

function decodeBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  if (pad === 2) base64 += "==";
  else if (pad === 3) base64 += "=";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const te = new TextEncoder();
const td = new TextDecoder();

describe("Test vectors from draft-ietf-jose-hpke-encrypt-16", () => {
  // Use @hpke/core directly for low-level decryption (bypass JoseEncrypt0
  // to verify raw interop with the draft's examples).
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  describe("Example 1: Integrated Encryption — Compact (Section 5.2)", () => {
    const compactJwe =
      "eyJhbGciOiJIUEtFLTAiLCJraWQiOiJ5Q25mYm1ZTVpjV3JLRHRfRGpOZWJS" +
      "Q0IxdnhWb3F2NHVtSjRXSzhSWWprIn0" +
      ".BLAJX8adrFsDKaoJAc3iy2dq-6jEH3Uv-bSgqIoDeREqpWglMoTS67XsXere" +
      "1ZYxiQKEFU6MbWe8O7vmdlSmcUk" +
      "." +
      ".NcN9ew5aijn8W7piLVRU8r2cOP0JKqxOF4RllVsJM4qsAfVXW5Ka6so9zdUm" +
      "XXNOXyCEk0wV_s8ICAnD4LbRa5TkhTeuhijIfAt9bQ2fMLOeyed3WyArs8yaM" +
      "raa9Zbh4i6SaHunM7jU_xoz_N2WbykSOSySmCO49H4mP3jLW9L_TYQfeVfYsr" +
      "B8clqokZ8h-3eQGNwmOPtkjWdpAfaHUsp4-HC9nRd6yrTU6mV65Nn2iYynu3X" +
      "kgy2Lm-kQKDavIEW3PBpEeiw6mtPJE9o8sT-0lZ9kpWtqog2XbNGEfjSOjujv" +
      "Ne1b0g4-FdNFMFO_fo0rxe902W1pGT7znv4Q-xBkIydK4ZwjiFN6dAXutnoco" +
      "c37A0Hr5esPLwHRTTrBFw" +
      ".";

    it("should decrypt using JoseEncrypt0.open()", async () => {
      const enc0 = createHpke0();
      const privateKey = await enc0.importPrivateJwk(jwkA1);
      const pt = await enc0.open(privateKey, compactJwe);
      assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
    });

    it("should decrypt using @hpke/core directly", async () => {
      const parts = compactJwe.split(".");
      const encodedProtectedHeader = parts[0];
      const encBytes = decodeBase64Url(parts[1]);
      const ciphertext = decodeBase64Url(parts[3]);

      const privateKey = await suite.kem.importKey(
        "raw",
        decodeBase64Url(jwkA1.d).buffer as ArrayBuffer,
        false,
      );

      const aad = te.encode(encodedProtectedHeader);
      const ctx = await suite.createRecipientContext({
        recipientKey: privateKey,
        enc: encBytes,
        info: new Uint8Array(0),
      });
      const pt = new Uint8Array(await ctx.open(ciphertext, aad));
      assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
    });
  });

  describe("Example 2: Integrated Encryption — Flattened JSON (Section 5.3)", () => {
    const example2 = {
      ciphertext:
        "LabI8_KIPDbymUSbyVctj8AfISXQ07sMt1xQ1lrS-0heU2jjejpQIK75K1KX" +
        "cvwn15E6Kil_tJ6LBcYCu02O1H8_aooJGuoLw1vEzQn16h498YX9e2SA2IcV" +
        "rJTkcCjL7YpF9fsAF3JEzGfsmmrpZPPVdxCn7g8dkGRcyulnHrNvBu4BFtub" +
        "-URtf-nYCFIJHZ4k-ul9fDddquicFzCxQonx66-ZX5nbj6azHG65tAZntd6VF" +
        "kRgihdxTvIpvTS4gfulQeKyShbiw-OCJNbzFdEnOKEMnsyqRjwG7iVrFEilFA" +
        "MsvLJ14-lcuR5btIkUntIwlnsfUa2Ytk33znCfAFN0wYukdDvJe-V0nnNUFl" +
        "OeLyYV0eEGisgC9dQQ1kFu3g",
      encrypted_key:
        "BAOlZ-VnbhQu4NOlTlDAVYwUJB-Q6YcWwnRNWK6YLSiHHlW4rN0qUzBJ3Rc" +
        "2_y8nkasn8nUVGBzdq7OhdKKiLq4",
      aad: "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
      protected:
        "eyJhbGciOiJIUEtFLTAiLCJraWQiOiJ5Q25mYm1ZTVpjV3JLRHRfRGpOZWJS" +
        "Q0IxdnhWb3F2NHVtSjRXSzhSWWprIn0",
    };

    it("should decrypt using @hpke/core with JWE AAD", async () => {
      const encBytes = decodeBase64Url(example2.encrypted_key);
      const ciphertext = decodeBase64Url(example2.ciphertext);

      const privateKey = await suite.kem.importKey(
        "raw",
        decodeBase64Url(jwkA1.d).buffer as ArrayBuffer,
        false,
      );

      // AAD for JSON with aad field: ASCII(protected || '.' || aad)
      const aad = te.encode(`${example2.protected}.${example2.aad}`);

      const ctx = await suite.createRecipientContext({
        recipientKey: privateKey,
        enc: encBytes,
        info: new Uint8Array(0),
      });
      const pt = new Uint8Array(await ctx.open(ciphertext, aad));
      assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);

      // Verify aad decodes to "The Fellowship of the Ring"
      assertEquals(
        td.decode(decodeBase64Url(example2.aad)),
        "The Fellowship of the Ring",
      );
    });
  });

  describe("Example 3: Key Encryption — General JSON (Section 6.3)", () => {
    const example3 = {
      ciphertext:
        "uF1XBbVZWhYm_pDbeJvI_fkuqFJiKd1WMP3O_BAGOP-LkpTLE3Et2VQNcOpP" +
        "AIBfyx8rUzshGqiOFOWzcoWZ3mIwYuDvvAW3-P1RCS8Dtq70JRvahO5O8sAN" +
        "1vzJg8_dyBPnwsQY6Cy3RhMD6sSSCjjSw0FYmmx67IiI2zJ6Wr8z69k0f34Z" +
        "Th43k4C-pTwaUSvjl2XI_YrUgdDVYmY_MJ5vmlPTcceMaefP8Onz_fx5xOcG" +
        "fnVBVz2gpMQPuQL8k5Rk5KJvPGfFfN6hrgWkK_LDzi4lrfnIrvNsk3BCBeZP" +
        "pc-n19-u7W4-GQxLjAlVyMHeGk5K4tU6gHB8PnnQ4ND5ZTtyXrJWQW-Qr1iF" +
        "ev6g",
      iv: "mLiHjYaQA42nPm1L",
      recipients: [
        {
          encrypted_key: "hU6b0hp4-y4ZoK1Qz8YWmDmqDmgTto3HW25-RyPhcLU",
          header: {
            alg: "HPKE-0-KE",
            kid: "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
            ek:
              "BGWPWLoD5BUjFEDIjMS-yvtcCXBn5A-kuv2RjzUY_2hKUjgZINqtEy1aHZ8dWxAiyApV5JafG76W8O_yZzy5T54",
          },
        },
      ],
      tag: "K22C64ZhFABEu2S2F00PLg",
      aad: "VGhlIEZlbGxvd3NoaXAgb2YgdGhlIFJpbmc",
      protected: "eyJlbmMiOiJBMTI4R0NNIn0",
    };

    it("should decrypt using JoseEncrypt.open()", async () => {
      const { ContentEncAlg } = await import("../mod.ts");
      const enc = createHpke0Ke(ContentEncAlg.A128GCM);
      const privateKey = await enc.importPrivateJwk(jwkA2);
      const pt = await enc.open(privateKey, example3);
      assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
    });

    it("should decrypt using @hpke/core + WebCrypto directly", async () => {
      const privateKey = await suite.kem.importKey(
        "raw",
        decodeBase64Url(jwkA2.d).buffer as ArrayBuffer,
        false,
      );

      const r = example3.recipients[0];
      const encBytes = decodeBase64Url(r.header.ek);
      const encryptedKey = decodeBase64Url(r.encrypted_key);

      // Build Recipient_structure:
      // "JOSE-HPKE rcpt" || 0xFF || "A128GCM" || 0xFF
      const context = te.encode("JOSE-HPKE rcpt");
      const algBytes = te.encode("A128GCM");
      const info = new Uint8Array(
        context.length + 1 + algBytes.length + 1,
      );
      info.set(context, 0);
      info[context.length] = 0xff;
      info.set(algBytes, context.length + 1);
      info[context.length + 1 + algBytes.length] = 0xff;

      // Unwrap CEK
      const ctx = await suite.createRecipientContext({
        recipientKey: privateKey,
        enc: encBytes,
        info,
      });
      const cek = new Uint8Array(
        await ctx.open(encryptedKey, new Uint8Array(0)),
      );

      // Decrypt content with AES-128-GCM
      const nonce = decodeBase64Url(example3.iv);
      const ct = decodeBase64Url(example3.ciphertext);
      const tag = decodeBase64Url(example3.tag);

      const combined = new Uint8Array(ct.length + tag.length);
      combined.set(ct);
      combined.set(tag, ct.length);

      const contentAad = te.encode(
        `${example3.protected}.${example3.aad}`,
      );

      const s = globalThis.crypto.subtle;
      const k = await s.importKey(
        "raw",
        cek.buffer as ArrayBuffer,
        "AES-GCM",
        false,
        [
          "decrypt",
        ],
      );
      const pt = new Uint8Array(
        await s.decrypt(
          {
            name: "AES-GCM",
            iv: nonce.buffer as ArrayBuffer,
            additionalData: contentAad.buffer as ArrayBuffer,
            tagLength: 128,
          },
          k,
          combined.buffer as ArrayBuffer,
        ),
      );
      assertEquals(td.decode(pt), EXPECTED_PLAINTEXT);
    });

    it("should have correct protected header", () => {
      const header = JSON.parse(
        td.decode(decodeBase64Url(example3.protected)),
      );
      assertEquals(header.enc, "A128GCM");
    });

    it("should have correct recipient header", () => {
      const r = example3.recipients[0];
      assertEquals(r.header.alg, "HPKE-0-KE");
      assertEquals(
        r.header.kid,
        "9CfUPiGcAcTp7oXgVbDStw2FEjka-_KHU_i-X3XMCEA",
      );
    });
  });
});
