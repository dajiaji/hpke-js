import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { loadCrypto } from "@hpke/common";
import {
  AeadId,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { Chacha20Poly1305 } from "../mod.ts";
import { chacha20poly1305 } from "../src/chacha/chacha.ts";

describe("Chacha20Poly1305", () => {
  describe("with valid parameters", () => {
    it("should have a correct AEAD object", () => {
      // assert
      const aead = new Chacha20Poly1305();
      assertEquals(typeof aead, "object");
      assertEquals(aead.id, AeadId.Chacha20Poly1305);
      assertEquals(aead.keySize, 32);
      assertEquals(aead.nonceSize, 12);
      assertEquals(aead.tagSize, 16);
    });
  });
});

describe("createEncryptionContext", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const cryptoApi = await loadCrypto();

      const aead = new Chacha20Poly1305();

      const iv = new Uint8Array(aead.nonceSize);
      const key = new Uint8Array(aead.keySize);
      cryptoApi.getRandomValues(key);
      cryptoApi.getRandomValues(iv);

      const te = new TextEncoder();
      const td = new TextDecoder();
      const ctx = await aead.createEncryptionContext(key.buffer as ArrayBuffer);
      const ct = await ctx.seal(
        iv.buffer as ArrayBuffer,
        te.encode("my-secret-message").buffer as ArrayBuffer,
        te.encode("aad").buffer as ArrayBuffer,
      );
      const pt = await ctx.open(
        iv.buffer as ArrayBuffer,
        ct,
        te.encode("aad").buffer as ArrayBuffer,
      );

      // assert
      assertEquals(td.decode(pt), "my-secret-message");
    });
  });
});

describe("CipherSuite", () => {
  describe("constructor with Chacha20Poly1305", () => {
    it("should have a correct ciphersuite", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Chacha20Poly1305(),
      });

      // assert
      assertEquals(suite.aead.id, AeadId.Chacha20Poly1305);
      assertEquals(suite.aead.keySize, 32);
      assertEquals(suite.aead.nonceSize, 12);
      assertEquals(suite.aead.tagSize, 16);
    });
  });

  describe("A README example of Chacha20Poly1305", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Chacha20Poly1305(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      assertEquals(sender.enc.byteLength, suite.kem.publicKeySize);

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });
});

describe("chacha20poly1305", () => {
  it("should accept misaligned nonces for encrypt and decrypt", () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    const nonceBytes = Uint8Array.from({ length: 12 }, (_, i) => i + 32);
    const aad = Uint8Array.from([1, 3, 3, 7]);
    const msg = Uint8Array.from([9, 8, 7, 6, 5, 4, 3, 2]);

    const nonceBacking = new Uint8Array(13);
    nonceBacking.set(nonceBytes, 1);
    const misalignedNonce = nonceBacking.subarray(1);

    const alignedCt = chacha20poly1305(key, nonceBytes, aad).encrypt(msg);
    const misalignedCt = chacha20poly1305(key, misalignedNonce, aad).encrypt(
      msg,
    );

    assertEquals(misalignedCt, alignedCt);
    assertEquals(
      chacha20poly1305(key, misalignedNonce, aad).decrypt(alignedCt),
      msg,
    );
  });

  it("should reject invalid decrypt keys with the same validation as encrypt", () => {
    const invalidKey = new Uint8Array(31);
    const nonce = new Uint8Array(12);
    const aad = new Uint8Array();
    const ciphertext = new Uint8Array(16);
    const expectedMessage =
      '"arx key" expected Uint8Array of length 32, got length=31';

    assertThrows(
      () => chacha20poly1305(invalidKey, nonce, aad).encrypt(new Uint8Array(1)),
      Error,
      expectedMessage,
    );
    assertThrows(
      () => chacha20poly1305(invalidKey, nonce, aad).decrypt(ciphertext),
      Error,
      expectedMessage,
    );
  });
});
