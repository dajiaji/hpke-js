import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { loadCrypto } from "@hpke/common";
import {
  AeadId,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";

import { Chacha20Poly1305 } from "../mod.ts";
import { keyWords, open, seal } from "../src/chacha/chacha.ts";

// One-shot AEAD helper over the internal seal()/open() functions.
function chacha20poly1305(key: Uint8Array, iv: Uint8Array, aad: Uint8Array) {
  return {
    encrypt: (msg: Uint8Array) => seal(keyWords(key), iv, aad, msg),
    decrypt: (ct: Uint8Array) => open(keyWords(key), iv, aad, ct),
  };
}

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
  it("rejects ciphertexts shorter than the tag", () => {
    const key = new Uint8Array(32);
    const nonce = new Uint8Array(12);
    const aad = new Uint8Array();
    assertThrows(
      () => chacha20poly1305(key, nonce, aad).decrypt(new Uint8Array(15)),
      Error,
      "ciphertext too short",
    );
  });

  it("returns rejected Promises for context validation and authentication failures", async () => {
    const ctx = new Chacha20Poly1305().createEncryptionContext(
      new Uint8Array(32),
    );
    const empty = new Uint8Array();
    await assertRejects(
      () => ctx.seal(new Uint8Array(11), empty, empty),
      Error,
      "nonce",
    );
    await assertRejects(
      () => ctx.open(new Uint8Array(11), new Uint8Array(16), empty),
      Error,
      "nonce",
    );
    const nonce = new Uint8Array(12);
    await assertRejects(
      () => ctx.open(nonce, new Uint8Array(15), empty),
      Error,
      "ciphertext too short",
    );
    const ct = new Uint8Array(await ctx.seal(nonce, empty, empty));
    ct[0] ^= 1;
    await assertRejects(() => ctx.open(nonce, ct, empty), Error, "invalid tag");
  });

  it("returns rejected Promises for invalid context keys", async () => {
    const nonce = new Uint8Array(12);
    const empty = new Uint8Array();
    for (const len of [0, 31, 33, 64]) {
      const ctx = new Chacha20Poly1305().createEncryptionContext(
        new Uint8Array(len),
      );
      await assertRejects(
        () => ctx.seal(nonce, empty, empty),
        Error,
        "invalid key length",
      );
      await assertRejects(
        () => ctx.open(nonce, new Uint8Array(16), empty),
        Error,
        "invalid key length",
      );
    }
  });

  it("accepts ArrayBuffer and non-Uint8Array view inputs without modifying them", async () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    const nonce = Uint8Array.from({ length: 12 }, (_, i) => i + 32);
    const aad = Uint8Array.from({ length: 6 }, (_, i) => i + 64);
    const msg = Uint8Array.from({ length: 100 }, (_, i) => i + 96);
    const expected = chacha20poly1305(key, nonce, aad).encrypt(msg);

    // Views into larger buffers, at an odd offset.
    const backing = new Uint8Array(1 + 32 + 12 + 6 + 100);
    backing.set(key, 1);
    backing.set(nonce, 33);
    backing.set(aad, 45);
    backing.set(msg, 51);
    const snapshot = backing.slice();
    const view = (offset: number, length: number) =>
      new DataView(backing.buffer, offset, length);

    const ctx = new Chacha20Poly1305().createEncryptionContext(view(1, 32));
    const ct = await ctx.seal(view(33, 12), view(51, 100), view(45, 6));
    assertEquals(new Uint8Array(ct), expected);
    assertEquals(backing, snapshot);

    const ctx2 = new Chacha20Poly1305().createEncryptionContext(
      key.buffer as ArrayBuffer,
    );
    const pt = await ctx2.open(
      nonce.buffer as ArrayBuffer,
      ct,
      new Uint16Array(aad.buffer),
    );
    assertEquals(new Uint8Array(pt), msg);
    // The returned buffers are exactly sized and independent of the inputs.
    assertEquals(ct.byteLength, msg.length + 16);
    assertEquals(pt.byteLength, msg.length);
  });

  it("accepts SharedArrayBuffer inputs and returns unshared buffers", async () => {
    const shared = (bytes: Uint8Array): SharedArrayBuffer => {
      const buf = new SharedArrayBuffer(bytes.length);
      new Uint8Array(buf).set(bytes);
      return buf;
    };
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    const nonce = Uint8Array.from({ length: 12 }, (_, i) => i + 32);
    const aad = Uint8Array.from({ length: 20 }, (_, i) => i + 64);
    const msg = Uint8Array.from({ length: 100 }, (_, i) => i + 96);
    const expected = chacha20poly1305(key, nonce, aad).encrypt(msg);

    const ctx = new Chacha20Poly1305().createEncryptionContext(shared(key));
    const ct = await ctx.seal(shared(nonce), shared(msg), shared(aad));
    assertEquals(ct instanceof ArrayBuffer, true);
    assertEquals(new Uint8Array(ct), expected);

    const pt = await ctx.open(
      shared(nonce),
      new Uint8Array(shared(expected)),
      shared(aad),
    );
    assertEquals(pt instanceof ArrayBuffer, true);
    assertEquals(new Uint8Array(pt), msg);
  });

  it("does not retain the caller's key buffer", async () => {
    const key = Uint8Array.from({ length: 32 }, (_, i) => i);
    const nonce = new Uint8Array(12);
    const empty = new Uint8Array();
    const msg = new Uint8Array(10);
    const ctx = new Chacha20Poly1305().createEncryptionContext(key);
    const before = await ctx.seal(nonce, msg, empty);
    key.fill(0xff);
    assertEquals(await ctx.seal(nonce, msg, empty), before);
  });

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
    const expectedMessage = "invalid key length";

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
