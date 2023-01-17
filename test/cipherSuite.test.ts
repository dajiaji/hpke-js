import { assertEquals, assertRejects, assertThrows } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import { Aead, Kdf, Kem } from "../src/identifiers.ts";
import { CipherSuite } from "../src/cipherSuite.ts";
import { isDeno } from "../src/utils/misc.ts";
import { loadCrypto } from "../src/webCrypto.ts";
import { concat } from "../src/utils/misc.ts";

import * as errors from "../src/errors.ts";

import { hexStringToBytes } from "./utils.ts";

describe("CipherSuite", () => {
  // RFC9180 A.1.
  describe("constructor with DhkemX25519HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have ciphersuites", async () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemX25519HkdfSha256);
      assertEquals(suite.kem, 0x0020);
      assertEquals(suite.kemSecretSize, 32);
      assertEquals(suite.kemEncSize, 32);
      assertEquals(suite.kemPublicKeySize, 32);
      assertEquals(suite.kemPrivateKeySize, 32);
      assertEquals(suite.kdf, Kdf.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, Aead.Aes128Gcm);
      assertEquals(suite.aead, 0x0001);

      const kemContext = await suite.kemContext();
      assertEquals(kemContext.id, Kem.DhkemX25519HkdfSha256);
      assertEquals(kemContext.id, 0x0020);
      assertEquals(kemContext.secretSize, 32);
      assertEquals(kemContext.encSize, 32);
      assertEquals(kemContext.publicKeySize, 32);
      assertEquals(kemContext.privateKeySize, 32);
    });
  });

  // RFC9180 A.2.
  describe("constructor with DhkemX25519HkdfSha256/HkdfSha256/ChaCha20Poly1305", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemX25519HkdfSha256);
      assertEquals(suite.kem, 0x0020);
      assertEquals(suite.kdf, Kdf.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, Aead.Chacha20Poly1305);
      assertEquals(suite.aead, 0x0003);
    });
  });

  // RFC9180 A.3.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem, 0x0010);
      assertEquals(suite.kdf, Kdf.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, Aead.Aes128Gcm);
      assertEquals(suite.aead, 0x0001);
    });
  });

  // RFC9180 A.4.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha512/Aes128Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes128Gcm,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem, 0x0010);
      assertEquals(suite.kdf, Kdf.HkdfSha512);
      assertEquals(suite.kdf, 0x0003);
      assertEquals(suite.aead, Aead.Aes128Gcm);
      assertEquals(suite.aead, 0x0001);
    });
  });

  // RFC9180 A.5.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/ChaCha20Poly1305", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem, 0x0010);
      assertEquals(suite.kdf, Kdf.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, Aead.Chacha20Poly1305);
      assertEquals(suite.aead, 0x0003);
    });
  });

  // RFC9180 A.6.
  describe("constructor with DhkemP521HkdfSha512/HkdfSha512/Aes256Gcm", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemP521HkdfSha512);
      assertEquals(suite.kem, 0x0012);
      assertEquals(suite.kdf, Kdf.HkdfSha512);
      assertEquals(suite.kdf, 0x0003);
      assertEquals(suite.aead, Aead.Aes256Gcm);
      assertEquals(suite.aead, 0x0002);
    });
  });

  // RFC9180 A.7.
  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should have ciphersuites", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      // assert
      assertEquals(suite.kem, Kem.DhkemP256HkdfSha256);
      assertEquals(suite.kem, 0x0010);
      assertEquals(suite.kdf, Kdf.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, Aead.ExportOnly);
      assertEquals(suite.aead, 0xFFFF);
    });
  });

  describe("constructor with DhkemP256HkdfSha256/HkdfSha256/ExportOnly", () => {
    it("should have ciphersuites", async () => {
      const suite: CipherSuite = new CipherSuite({
        kem: Kem.DhkemSecp256K1HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });
      const kem = await suite.kemContext();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 65);
      assertEquals(kem.publicKeySize, 65);
      assertEquals(kem.privateKeySize, 32);

      // assert
      assertEquals(suite.kem, Kem.DhkemSecp256K1HkdfSha256);
      assertEquals(suite.kem, 0x0013);
      assertEquals(suite.kdf, Kdf.HkdfSha256);
      assertEquals(suite.kdf, 0x0001);
      assertEquals(suite.aead, Aead.ExportOnly);
      assertEquals(suite.aead, 0xFFFF);
    });
  });

  describe("constructor with invalid KEM id", () => {
    it("should throw InvalidParamError", () => {
      assertThrows(
        () =>
          new CipherSuite({
            kem: -1,
            kdf: Kdf.HkdfSha256,
            aead: Aead.Aes128Gcm,
          }),
        errors.InvalidParamError,
        "InvalidParamError: Invalid KEM id",
      );
    });
  });

  describe("constructor with invalid KDF id", () => {
    it("should throw InvalidParamError", () => {
      assertThrows(
        () =>
          new CipherSuite({
            kem: Kem.DhkemP256HkdfSha256,
            kdf: -1,
            aead: Aead.Aes128Gcm,
          }),
        errors.InvalidParamError,
        "InvalidParamError: Invalid KDF id",
      );
    });
  });

  describe("constructor with invalid AEAD id", () => {
    it("should throw InvalidParamError", () => {
      assertThrows(
        () =>
          new CipherSuite({
            kem: Kem.DhkemP256HkdfSha256,
            kdf: Kdf.HkdfSha256,
            aead: -1,
          }),
        errors.InvalidParamError,
        "InvalidParamError: Invalid AEAD id",
      );
    });
  });

  describe("A README example of Base mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      await assertRejects(() => recipient.seal(pt), errors.SealError);
      await assertRejects(() => sender.open(ct), errors.OpenError);
    });
  });

  describe("A README example of Base mode (Kem.DhkemP384HkdfSha384/Kdf.HkdfSha384)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Base mode (Kem.DhkemP521HkdfSha512/Kdf.HkdfSha384)", () => {
    it("should work normally", async () => {
      if (isDeno()) {
        return;
      }

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Base mode (Kem.DhkemX25519HkdfSha256/Kdf.HkdfSha384)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Base mode (Kem.DhkemSecp256K1HkdfSha256/Kdf.HkdfSha256)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemSecp256K1HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Base mode (Kem.DhkemX448HkdfSha256/Kdf.HkdfSha384)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Base mode (ExportOnly)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(te.encode("jugemujugemu"), 32);
      const pskR = recipient.export(te.encode("jugemujugemu"), 32);
      assertEquals(pskR, pskS);

      // other functions are disabled.
      await assertRejects(
        () => sender.seal(te.encode("my-secret-message")),
        errors.NotSupportedError,
      );
      await assertRejects(
        () => sender.open(te.encode("xxxxxxxxxxxxxxxxx")),
        errors.NotSupportedError,
      );
      await assertRejects(
        () => sender.setupBidirectional(te.encode("a"), te.encode("b")),
        errors.NotSupportedError,
      );
    });
  });

  describe("A README example of Base mode (ExportOnly/X25519)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      const te = new TextEncoder();

      // export
      const pskS = sender.export(te.encode("jugemujugemu"), 32);
      const pskR = recipient.export(te.encode("jugemujugemu"), 32);
      assertEquals(pskR, pskS);

      // other functions are disabled.
      await assertRejects(
        () => sender.seal(te.encode("my-secret-message")),
        errors.NotSupportedError,
      );
      await assertRejects(
        () => sender.open(te.encode("xxxxxxxxxxxxxxxxx")),
        errors.NotSupportedError,
      );
      await assertRejects(
        () => sender.setupBidirectional(te.encode("a"), te.encode("b")),
        errors.NotSupportedError,
      );
    });
  });

  describe("A README example of PSK mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of Auth mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of AuthPSK mode", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of AuthPSK mode (X25519)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("A README example of AuthPSK mode (X448)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
        psk: {
          id: new TextEncoder().encode("our-pre-shared-key-id"),
          key: new TextEncoder().encode("jugemujugemugokounosurikirekaija"),
        },
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("createRecipientContext with a private key as recipientKey", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("createSenderContext with a privatekey as senderKey", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const skp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        senderKey: skp.privateKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        senderPublicKey: skp.publicKey,
      });

      // encrypt
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("seal and open (single-shot apis)", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      // encrypt
      const { ct, enc } = await suite.seal(
        {
          recipientPublicKey: rkp.publicKey,
        },
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await suite.open(
        {
          recipientKey: rkp,
          enc: enc,
        },
        ct,
      );

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally (X25519)", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      // encrypt
      const { ct, enc } = await suite.seal(
        {
          recipientPublicKey: rkp.publicKey,
        },
        new TextEncoder().encode("my-secret-message"),
      );

      // decrypt
      const pt = await suite.open(
        {
          recipientKey: rkp,
          enc: enc,
        },
        ct,
      );

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });

  describe("bidirectional seal and open", () => {
    it("should work normally (DhkemP256HkdfSha256)", async () => {
      const te = new TextEncoder();

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // setup bidirectional encryption
      await sender.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      // encrypt
      const ct = await sender.seal(te.encode("my-secret-message"));

      // decrypt
      const pt = await recipient.open(ct);

      // encrypt reversely
      const rct = await recipient.seal(te.encode("my-secret-message"));

      // decrypt reversely
      const rpt = await sender.open(rct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      assertEquals(new TextDecoder().decode(rpt), "my-secret-message");
    });

    it("should work normally (DhkemX25519HkdfSha256)", async () => {
      const te = new TextEncoder();

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // setup bidirectional encryption
      await sender.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      // encrypt
      const ct = await sender.seal(te.encode("my-secret-message"));

      // decrypt
      const pt = await recipient.open(ct);

      // encrypt reversely
      const rct = await recipient.seal(te.encode("my-secret-message"));

      // decrypt reversely
      const rpt = await sender.open(rct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      assertEquals(new TextDecoder().decode(rpt), "my-secret-message");
    });

    it("should work normally (DhkemX448HkdfSha512)", async () => {
      const te = new TextEncoder();

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // setup bidirectional encryption
      await sender.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      // encrypt
      const ct = await sender.seal(te.encode("my-secret-message"));

      // decrypt
      const pt = await recipient.open(ct);

      // encrypt reversely
      const rct = await recipient.seal(te.encode("my-secret-message"));

      // decrypt reversely
      const rpt = await sender.open(rct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
      assertEquals(new TextDecoder().decode(rpt), "my-secret-message");
    });
  });

  describe("seal empty byte string", () => {
    it("should work normally", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });

      // encrypt
      const ct = await sender.seal(new TextEncoder().encode(""));

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "");
    });
  });

  describe("deriveKeyPair with too long ikm", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      await assertRejects(
        () => suite.deriveKeyPair((new Uint8Array(129)).buffer),
        errors.InvalidParamError,
        "Too long ikm",
      );
    });
  });

  describe("createSenderContext with too long info", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            info: (new Uint8Array(129)).buffer,
            recipientPublicKey: rkp.publicKey,
          }),
        errors.InvalidParamError,
        "Too long info",
      );
    });
  });

  describe("createSenderContext with too long psk.key", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            psk: {
              key: (new Uint8Array(129)).buffer,
              id: new Uint8Array([1, 2, 3, 4]),
            },
            recipientPublicKey: rkp.publicKey,
          }),
        errors.InvalidParamError,
        "Too long psk.key",
      );
    });
  });

  describe("createSenderContext with short psk.key", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            psk: {
              key: (new Uint8Array(31)).buffer,
              id: new Uint8Array([1, 2, 3, 4]),
            },
            recipientPublicKey: rkp.publicKey,
          }),
        errors.InvalidParamError,
        "PSK must have at least 32 bytes",
      );
    });
  });

  describe("createSenderContext with too long psk.id", () => {
    it("should throw InvalidParamError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      await assertRejects(
        () =>
          suite.createSenderContext({
            psk: {
              key: new Uint8Array(32),
              id: (new Uint8Array(129)).buffer,
            },
            recipientPublicKey: rkp.publicKey,
          }),
        errors.InvalidParamError,
        "Too long psk.id",
      );
    });
  });

  describe("importKey with invalid EC(P-256) public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexStringToBytes(kStr);

      // assert
      await assertRejects(
        () => suite.importKey("raw", k),
        errors.DeserializeError,
      );
    });
  });

  describe("importKey with invalid EC(P-256) private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexStringToBytes(kStr);

      // assert
      await assertRejects(
        () => suite.importKey("raw", k, false),
        errors.DeserializeError,
      );
    });
  });

  describe("importKey with invalid x25519 public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexStringToBytes(kStr);

      // assert
      await assertRejects(
        () => suite.importKey("raw", k),
        errors.DeserializeError,
      );
    });
  });

  describe("importKey with invalid x25519 private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexStringToBytes(kStr);

      // assert
      await assertRejects(
        () => suite.importKey("raw", k, false),
        errors.DeserializeError,
      );
    });
  });

  describe("importKey with invalid x448 public key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexStringToBytes(kStr);

      // assert
      await assertRejects(
        () => suite.importKey("raw", k),
        errors.DeserializeError,
      );
    });
  });

  describe("importKey with invalid x448 private key", () => {
    it("should throw DeserializeError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemX448HkdfSha512,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const kStr = "aabbccddeeff";
      const k = hexStringToBytes(kStr);

      // assert
      await assertRejects(
        () => suite.importKey("raw", k, false),
        errors.DeserializeError,
      );
    });
  });

  describe("A README example of Oblivious HTTP", () => {
    it("should work normally", async () => {
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const rkp = await suite.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.");
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response"),
        suite.aeadKeySize,
      );

      const responseNonce = new Uint8Array(suite.aeadKeySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce);

      const kdfS = await suite.kdfContext();
      const prkS = await kdfS.extract(saltS, new Uint8Array(secretS));
      const keyS = await kdfS.expand(
        prkS,
        te.encode("key"),
        suite.aeadKeySize,
      );
      const nonceS = await kdfS.expand(
        prkS,
        te.encode("nonce"),
        suite.aeadNonceSize,
      );

      const aeadKeyS = await suite.createAeadKey(keyS);
      const ct = await aeadKeyS.seal(nonceS, response, te.encode(""));
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response"),
        suite.aeadKeySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aeadKeySize),
      );
      const kdfR = await suite.kdfContext();
      const prkR = await kdfR.extract(
        saltR,
        new Uint8Array(secretR),
      );
      const keyR = await kdfR.expand(prkR, te.encode("key"), suite.aeadKeySize);
      const nonceR = await kdfR.expand(
        prkR,
        te.encode("nonce"),
        suite.aeadNonceSize,
      );
      const aeadKeyR = await suite.createAeadKey(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aeadKeySize),
        te.encode(""),
      );

      // pt === "This is the response."
      assertEquals(response, new Uint8Array(pt));
    });
  });

  describe("A README example of Oblivious HTTP (HKDF-SHA384)", () => {
    it("should work normally", async () => {
      if (isDeno()) {
        return;
      }
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes256Gcm,
      });
      const rkp = await suite.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.");
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response"),
        suite.aeadKeySize,
      );

      const responseNonce = new Uint8Array(suite.aeadKeySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce);

      const kdfS = await suite.kdfContext();
      const prkS = await kdfS.extract(saltS, new Uint8Array(secretS));
      const keyS = await kdfS.expand(
        prkS,
        te.encode("key"),
        suite.aeadKeySize,
      );
      const nonceS = await kdfS.expand(
        prkS,
        te.encode("nonce"),
        suite.aeadNonceSize,
      );

      const aeadKeyS = await suite.createAeadKey(keyS);
      const ct = await aeadKeyS.seal(nonceS, response, te.encode(""));
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response"),
        suite.aeadKeySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aeadKeySize),
      );
      const kdfR = await suite.kdfContext();
      const prkR = await kdfR.extract(
        saltR,
        new Uint8Array(secretR),
      );
      const keyR = await kdfR.expand(prkR, te.encode("key"), suite.aeadKeySize);
      const nonceR = await kdfR.expand(
        prkR,
        te.encode("nonce"),
        suite.aeadNonceSize,
      );
      const aeadKeyR = await suite.createAeadKey(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aeadKeySize),
        te.encode(""),
      );

      // pt === "This is the response."
      assertEquals(response, new Uint8Array(pt));
    });
  });

  describe("A README example of Oblivious HTTP (HKDF-SHA512)", () => {
    it("should work normally", async () => {
      if (isDeno()) {
        return;
      }
      const te = new TextEncoder();
      const cryptoApi = await loadCrypto();

      const suite = new CipherSuite({
        kem: Kem.DhkemP521HkdfSha512,
        kdf: Kdf.HkdfSha512,
        aead: Aead.Aes256Gcm,
      });
      const rkp = await suite.generateKeyPair();

      // The sender (OHTTP client) side:
      const response = te.encode("This is the response.");
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const secretS = await sender.export(
        te.encode("message/bhttp response"),
        suite.aeadKeySize,
      );

      const responseNonce = new Uint8Array(suite.aeadKeySize);
      cryptoApi.getRandomValues(responseNonce);
      const saltS = concat(new Uint8Array(sender.enc), responseNonce);

      const kdfS = await suite.kdfContext();
      const prkS = await kdfS.extract(saltS, new Uint8Array(secretS));
      const keyS = await kdfS.expand(
        prkS,
        te.encode("key"),
        suite.aeadKeySize,
      );
      const nonceS = await kdfS.expand(
        prkS,
        te.encode("nonce"),
        suite.aeadNonceSize,
      );

      const aeadKeyS = await suite.createAeadKey(keyS);
      const ct = await aeadKeyS.seal(nonceS, response, te.encode(""));
      const encResponse = concat(responseNonce, new Uint8Array(ct));

      // The recipient (OHTTP server) side:
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp.privateKey,
        enc: sender.enc,
      });

      const secretR = await recipient.export(
        te.encode("message/bhttp response"),
        suite.aeadKeySize,
      );

      const saltR = concat(
        new Uint8Array(sender.enc),
        encResponse.slice(0, suite.aeadKeySize),
      );
      const kdfR = await suite.kdfContext();
      const prkR = await kdfR.extract(
        saltR,
        new Uint8Array(secretR),
      );
      const keyR = await kdfR.expand(prkR, te.encode("key"), suite.aeadKeySize);
      const nonceR = await kdfR.expand(
        prkR,
        te.encode("nonce"),
        suite.aeadNonceSize,
      );
      const aeadKeyR = await suite.createAeadKey(keyR);
      const pt = await aeadKeyR.open(
        nonceR,
        encResponse.slice(suite.aeadKeySize),
        te.encode(""),
      );

      // pt === "This is the response."
      assertEquals(response, new Uint8Array(pt));
    });
  });
});
