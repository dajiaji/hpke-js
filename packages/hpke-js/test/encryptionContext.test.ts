import { assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  Aes128Gcm,
  CipherSuite,
  DecapError,
  DeserializeError,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  EncapError,
  ExportError,
  HkdfSha256,
  HkdfSha384,
  InvalidParamError,
  NotSupportedError,
  OpenError,
} from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";

describe("open", () => {
  describe("by sender", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // assert
      await assertRejects(() => sender.open(ct), NotSupportedError);
    });
  });

  describe("by another recipient (AES-128-GCM)", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp1 = await suite.kem.generateKeyPair();
      const rkp2 = await suite.kem.generateKeyPair();

      const sender1 = await suite.createSenderContext({
        recipientPublicKey: rkp1.publicKey,
      });

      const recipient1 = await suite.createRecipientContext({
        recipientKey: rkp1,
        enc: sender1.enc,
      });

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      const ct1 = await sender1.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );
      await assertRejects(() =>
        recipient1.seal(
          new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
        ), NotSupportedError);

      // assert
      await assertRejects(() => recipient2.open(ct1), OpenError);
    });
  });

  describe("by another recipient (ChaCha20/Poly1305)", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp1 = await suite.kem.generateKeyPair();
      const rkp2 = await suite.kem.generateKeyPair();

      const sender1 = await suite.createSenderContext({
        recipientPublicKey: rkp1.publicKey,
      });

      const recipient1 = await suite.createRecipientContext({
        recipientKey: rkp1,
        enc: sender1.enc,
      });

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      const ct1 = await sender1.seal(
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );
      await assertRejects(
        () =>
          recipient1.seal(
            new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
          ),
        NotSupportedError,
      );

      // assert
      await assertRejects(() => recipient2.open(ct1), OpenError);
    });
  });
});

describe("export", () => {
  describe("with invalid argument", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const te = new TextEncoder();

      // assert
      await assertRejects(
        () => sender.export(te.encode("info").buffer as ArrayBuffer, -1),
        ExportError,
      );
    });
  });

  describe("with invalid argument", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const te = new TextEncoder();

      // assert
      await assertRejects(
        () => sender.export(te.encode("info").buffer as ArrayBuffer, -1),
        ExportError,
      );
    });
  });

  describe("with too long exporter_context", () => {
    it("should throw InvalidParamError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      // assert
      await assertRejects(
        () => sender.export(new Uint8Array(8193).buffer as ArrayBuffer, 32),
        InvalidParamError,
        "Too long exporter context",
      );
    });
  });
});

describe("createSenderContext", () => {
  describe("with invalid recipientPublicKey", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const suiteX = new CipherSuite({
        kem: new DhkemP384HkdfSha384(),
        kdf: new HkdfSha384(),
        aead: new Aes128Gcm(),
      });

      const rkpX = await suiteX.kem.generateKeyPair();

      // assert
      await assertRejects(
        () =>
          suite.createSenderContext({
            recipientPublicKey: rkpX.publicKey,
          }),
        EncapError,
      );
    });
  });
});

describe("createRecipientContext", () => {
  describe("with invalid enc", () => {
    it("should throw DeserializeError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const suiteX = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();
      const rkpX = await suiteX.kem.generateKeyPair();

      const senderX = await suiteX.createSenderContext({
        recipientPublicKey: rkpX.publicKey,
      });

      // assert
      await assertRejects(
        () =>
          suite.createRecipientContext({
            recipientKey: rkp,
            enc: senderX.enc,
          }),
        DeserializeError,
      );
    });
  });

  describe("with invalid enc (X25519)", () => {
    it("should throw DeserializeError", async () => {
      const suite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const suiteX = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();
      const rkpX = await suiteX.kem.generateKeyPair();

      const senderX = await suiteX.createSenderContext({
        recipientPublicKey: rkpX.publicKey,
      });

      // assert
      await assertRejects(
        () =>
          suite.createRecipientContext({
            recipientKey: rkp,
            enc: senderX.enc,
          }),
        DeserializeError,
      );
    });
  });

  describe("with invalid recipientKey", () => {
    it("should throw DecapError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: new DhkemP256HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const suiteX = new CipherSuite({
        kem: new DhkemP384HkdfSha384(),
        kdf: new HkdfSha384(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();
      const rkpX = await suiteX.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      // assert
      await assertRejects(
        () =>
          suite.createRecipientContext({
            recipientKey: rkpX,
            enc: sender.enc,
          }),
        DecapError,
      );
    });
  });
});
