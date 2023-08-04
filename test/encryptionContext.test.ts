import { assertEquals, assertRejects, assertThrows } from "testing/asserts.ts";

import { describe, it } from "testing/bdd.ts";

import { CipherSuite } from "../src/cipherSuite.ts";
import { EncryptionContextImpl } from "../src/encryptionContext.ts";
import { AeadId, KdfId, KemId } from "../src/identifiers.ts";
import { HkdfSha256 } from "../src/kdfs/hkdfSha256.ts";
import { loadSubtleCrypto } from "../src/webCrypto.ts";
import { i2Osp } from "../src/utils/misc.ts";
import { ExportOnly } from "../src/aeads/exportOnly.ts";
import { Aes128Gcm } from "../src/aeads/aesGcm.ts";

import * as consts from "../src/consts.ts";
import * as errors from "../src/errors.ts";

const DUMMY_BYTES_12 = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
const DUMMY_BYTES_16 = new Uint8Array(
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
);

describe("constructor", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();
      const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      kdf.init(api, suiteId);

      const key = DUMMY_BYTES_16.buffer;
      const baseNonce = DUMMY_BYTES_12;
      const seq = 0;

      const params = {
        aead: new Aes128Gcm(),
        nK: 16,
        nN: 12,
        nT: 16,
        exporterSecret: DUMMY_BYTES_16.buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      // assert
      params.aead.init(api);
      assertEquals(
        typeof new EncryptionContextImpl(api, kdf, params),
        "object",
      );
    });
  });

  describe("with invalid aead id", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      kdf.init(api, suiteId);

      const key = DUMMY_BYTES_16.buffer;
      const baseNonce = DUMMY_BYTES_12;
      const seq = 0;

      const params = {
        aead: new ExportOnly(), // invalid
        nK: 16,
        nN: 12,
        nT: 16,
        exporterSecret: DUMMY_BYTES_16.buffer,
        key: key,
        baseNonce: baseNonce,
        seq: seq,
      };

      // assert
      params.aead.init(api);
      assertThrows(
        () => {
          new EncryptionContextImpl(api, kdf, params);
        },
        Error,
        "NotSupportedError: createEncryptionContext() is not supported on ExportOnly",
      );
    });
  });
});

describe("open", () => {
  describe("by sender", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );

      // assert
      await assertRejects(() => sender.open(ct), errors.NotSupportedError);
    });
  });

  describe("by another recipient (AES-128-GCM)", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
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

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      const ct1 = await sender1.seal(
        new TextEncoder().encode("my-secret-message"),
      );
      await assertRejects(() =>
        recipient1.seal(
          new TextEncoder().encode("my-secret-message"),
        ), errors.NotSupportedError);

      // assert
      await assertRejects(() => recipient2.open(ct1), errors.OpenError);
    });
  });

  describe("by another recipient (ChaCha20/Poly1305)", () => {
    it("should throw OpenError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Chacha20Poly1305,
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

      const sender2 = await suite.createSenderContext({
        recipientPublicKey: rkp2.publicKey,
      });

      const recipient2 = await suite.createRecipientContext({
        recipientKey: rkp2,
        enc: sender2.enc,
      });

      const ct1 = await sender1.seal(
        new TextEncoder().encode("my-secret-message"),
      );
      await assertRejects(
        () => recipient1.seal(new TextEncoder().encode("my-secret-message")),
        errors.NotSupportedError,
      );

      // assert
      await assertRejects(() => recipient2.open(ct1), errors.OpenError);
    });
  });
});

describe("export", () => {
  describe("with invalid argument", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.ExportOnly,
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

  describe("with invalid argument", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.ExportOnly,
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

  describe("with too long exporter_context", () => {
    it("should throw InvalidParamError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.ExportOnly,
      });

      const rkp = await suite.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      // assert
      await assertRejects(
        () => sender.export(new Uint8Array(8193), 32),
        errors.InvalidParamError,
        "Too long exporter context",
      );
    });
  });
});

describe("createSenderContext", () => {
  describe("with invalid recipientPublicKey", () => {
    it("should throw ExportError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
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
});

describe("createRecipientContext", () => {
  describe("with invalid enc", () => {
    it("should throw DeserializeError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
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

  describe("with invalid enc (X25519)", () => {
    it("should throw DeserializeError", async () => {
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
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

  describe("with invalid recipientKey", () => {
    it("should throw DecapError", async () => {
      // setup
      const suite = new CipherSuite({
        kem: KemId.DhkemP256HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Aes128Gcm,
      });

      const suiteX = new CipherSuite({
        kem: KemId.DhkemP384HkdfSha384,
        kdf: KdfId.HkdfSha384,
        aead: AeadId.Aes128Gcm,
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

  describe("without key info", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const suiteId = new Uint8Array(consts.SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      kdf.init(api, suiteId);
      const params = {
        aead: new Aes128Gcm(),
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
          new EncryptionContextImpl(api, kdf, params);
        },
        Error,
        "Required parameters are missing",
      );
    });
  });
});

// describe('incrementSeq reaches upper limit', () => {
//   it('should throw Error', async () => {
//     const api = await loadSubtleCrypto();
//     const kdf = new KdfContext(api, {
//       kem: KemId.DhkemP256HkdfSha256,
//       kdf: KdfId.HkdfSha256,
//       aead: AeadId.Aes128Gcm,
//     });

//     const key = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer;
//     const baseNonce = new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1]);
//     const seq = Number.MAX_SAFE_INTEGER;

//     const params = {
//       aead: AeadId.Aes128Gcm,
//       nK: 16,
//       nN: 12,
//       nT: 16,
//       exporterSecret: new Uint8Array([1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]).buffer,
//       key: key,
//       baseNonce: baseNonce,
//       seq: seq,
//     };
//     const ec = new EncryptionContext(api, kdf, params);
//     let ki = { key: createEncryptionContext(AeadId.Aes128Gcm, key, api), baseNonce: baseNonce, seq: seq };
//     ec.incrementSeq(ki);
//     assertThrows(() => { ec.incrementSeq(ki); }, errors.MessageLimitReachedError, 'Message limit reached');
//   });
// });
