import {
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.142.0/testing/asserts.ts";

import { describe, it } from "https://deno.land/std@0.142.0/testing/bdd.ts";

import { CipherSuite } from "../src/cipherSuite.ts";
import { EncryptionContext } from "../src/encryptionContext.ts";
import { Aead, Kdf, Kem } from "../src/identifiers.ts";
import { KdfContext } from "../src/kdfContext.ts";
import { isDeno } from "../src/utils/misc.ts";
import { loadSubtleCrypto } from "../src/webCrypto.ts";
import * as errors from "../src/errors.ts";

describe("CipherSuite", () => {
  describe("open by another recipient (AES-128-GCM)", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const rkp1 = await suite.generateKeyPair();
      const rkp2 = await suite.generateKeyPair();

      const sender1 = await suite.createSenderContext({
        recipientPublicKey: rkp1.publicKey,
      });

      const recipient1 = await suite.createRecipientContext({
        recipientKey: rkp1,
        enc: sender1.enc,
      });

      const te = new TextEncoder();

      await sender1.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient1.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      await sender2.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient2.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      const ct1 = await sender1.seal(
        new TextEncoder().encode("my-secret-message"),
      );
      const ct2 = await recipient1.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // assert
      await assertRejects(() => recipient2.open(ct1), errors.OpenError);
      await assertRejects(() => sender2.open(ct2), errors.OpenError);
    });
  });

  describe("open by another recipient (ChaCha20/Poly1305)", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Chacha20Poly1305,
      });

      const rkp1 = await suite.generateKeyPair();
      const rkp2 = await suite.generateKeyPair();

      const sender1 = await suite.createSenderContext({
        recipientPublicKey: rkp1.publicKey,
      });

      const recipient1 = await suite.createRecipientContext({
        recipientKey: rkp1,
        enc: sender1.enc,
      });

      const te = new TextEncoder();

      await sender1.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient1.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      await sender2.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );
      await recipient2.setupBidirectional(
        te.encode("seed-for-key"),
        te.encode("seed-for-nonce"),
      );

      const ct1 = await sender1.seal(
        new TextEncoder().encode("my-secret-message"),
      );
      const ct2 = await recipient1.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // assert
      await assertRejects(() => recipient2.open(ct1), errors.OpenError);
      await assertRejects(() => sender2.open(ct2), errors.OpenError);
    });
  });

  describe("export with invalid argument", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const te = new TextEncoder();

      // assert
      await assertRejects(
        () => sender.export(te.encode("info"), -1),
        errors.ExportError,
      );
    });
  });

  describe("export with invalid argument", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const te = new TextEncoder();

      // assert
      await assertRejects(
        () => sender.export(te.encode("info"), -1),
        errors.ExportError,
      );
    });
  });

  describe("export with too long exporter_context", () => {
    it("should throw InvalidParamError", async () => {
      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      // assert
      await assertRejects(
        () => sender.export(new Uint8Array(129), 32),
        errors.InvalidParamError,
        "Too long exporter context",
      );
    });
  });

  describe("createSenderContext with invalid recipientPublicKey", () => {
    it("should throw ExportError", async () => {
      if (isDeno()) {
        return;
      }

      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkpX = await suiteX.generateKeyPair();

      // assert
      await assertRejects(
        () =>
          suite.createSenderContext({
            recipientPublicKey: rkpX.publicKey,
          }),
        errors.EncapError,
        "Invalid public key for the ciphersuite",
      );
    });
  });

  describe("createRecipientContext with invalid enc", () => {
    it("should throw DeserializeError", async () => {
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const rkpX = await suiteX.generateKeyPair();

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
        errors.DeserializeError,
        "Invalid public key for the ciphersuite",
      );
    });
  });

  describe("createRecipientContext with invalid enc (X25519)", () => {
    it("should throw DeserializeError", async () => {
      if (isDeno()) {
        return;
      }

      const suite = new CipherSuite({
        kem: Kem.DhkemX25519HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const rkpX = await suiteX.generateKeyPair();

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
        errors.DeserializeError,
        "Invalid public key for the ciphersuite",
      );
    });
  });

  describe("createRecipientContext with invalid recipientKey", () => {
    it("should throw DecapError", async () => {
      if (isDeno()) {
        return;
      }

      // setup
      const suite = new CipherSuite({
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: Kem.DhkemP384HkdfSha384,
        kdf: Kdf.HkdfSha384,
        aead: Aead.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();
      const rkpX = await suiteX.generateKeyPair();

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
        errors.DecapError,
        "Invalid public key for the ciphersuite",
      );
    });
  });

  describe("constructor without key info", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });
      const params = {
        aead: Aead.Aes128Gcm,
        nK: 16,
        nN: 12,
        nT: 16,
        exporterSecret: new Uint8Array([
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
          1,
        ]),
      };

      // assert
      assertThrows(
        () => {
          new EncryptionContext(api, kdf, params);
        },
        Error,
        "Required parameters are missing",
      );
    });
  });

  describe("constructor with invalid aead id", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const key =
        new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]).buffer;
      const baseNonce = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
      const seq = 0;

      const params = {
        aead: Aead.ExportOnly, // invalid
        nK: 16,
        nN: 12,
        nT: 16,
        exporterSecret:
          new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
            .buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      // assert
      assertThrows(
        () => {
          new EncryptionContext(api, kdf, params);
        },
        Error,
        "Invalid or unsupported AEAD id",
      );
    });
  });

  // describe('incrementSeq reaches upper limit', () => {
  //   it('should throw Error', async () => {
  //     const api = await loadSubtleCrypto();
  //     const kdf = new KdfContext(api, {
  //       kem: Kem.DhkemP256HkdfSha256,
  //       kdf: Kdf.HkdfSha256,
  //       aead: Aead.Aes128Gcm,
  //     });

  //     const key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer;
  //     const baseNonce = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1]);
  //     const seq = Number.MAX_SAFE_INTEGER;

  //     const params = {
  //       aead: Aead.Aes128Gcm,
  //       nK: 16,
  //       nN: 12,
  //       nT: 16,
  //       exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer,
  //       key: key,
  //       baseNonce: baseNonce,
  //       seq: seq,
  //     };
  //     const ec = new EncryptionContext(api, kdf, params);
  //     let ki = { key: createAeadKey(Aead.Aes128Gcm, key, api), baseNonce: baseNonce, seq: seq };
  //     ec.incrementSeq(ki);
  //     assertThrows(() => { ec.incrementSeq(ki); }, errors.MessageLimitReachedError, 'Message limit reached');
  //   });
  // });

  describe("setupBidirectional with invalid _nK", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const key =
        new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]).buffer;
      const baseNonce = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
      const seq = 0;

      const params = {
        aead: Aead.Aes128Gcm,
        nK: -1, // invalid
        nN: 12,
        nT: 16,
        exporterSecret:
          new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
            .buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      const te = new TextEncoder();
      const ec = new EncryptionContext(api, kdf, params);

      // assert
      await assertRejects(
        () => ec.setupBidirectional(te.encode("jyugemu"), te.encode("jyugemu")),
        errors.ExportError,
      );
    });
  });

  describe("setupBidirectional with invalid _nN", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const kdf = new KdfContext(api, {
        kem: Kem.DhkemP256HkdfSha256,
        kdf: Kdf.HkdfSha256,
        aead: Aead.Aes128Gcm,
      });

      const key =
        new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]).buffer;
      const baseNonce = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
      const seq = 0;

      const params = {
        aead: Aead.Aes128Gcm,
        nK: 16,
        nN: -1, // invalid
        nT: 16,
        exporterSecret:
          new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
            .buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      const te = new TextEncoder();
      const ec = new EncryptionContext(api, kdf, params);

      // assert
      await assertRejects(
        () => ec.setupBidirectional(te.encode("jyugemu"), te.encode("jyugemu")),
        errors.ExportError,
      );
    });
  });
});
