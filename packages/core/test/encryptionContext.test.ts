import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { i2Osp, loadSubtleCrypto } from "@hpke/common";

import {
  AeadId,
  Aes128Gcm,
  CipherSuite,
  DecapError,
  DhkemP256HkdfSha256,
  DhkemP384HkdfSha384,
  EncapError,
  ExportError,
  ExportOnly,
  HkdfSha256,
  HkdfSha384,
  InvalidParamError,
  KdfId,
  KemId,
  NotSupportedError,
  OpenError,
} from "../mod.ts";
import { EncryptionContextImpl } from "../src/encryptionContext.ts";

// deno-fmt-ignore
const SUITE_ID_HEADER_HPKE = new Uint8Array([
  72, 80, 75, 69, 0, 0, 0, 0, 0, 0,
]);
const DUMMY_BYTES_12 = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
const DUMMY_BYTES_16 = new Uint8Array(
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
);

describe("constructor", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const api = await loadSubtleCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      kdf.init(suiteId);

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
      assertEquals(
        typeof new EncryptionContextImpl(api, kdf, params),
        "object",
      );
    });
  });

  describe("with invalid aead id", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      kdf.init(suiteId);

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
      assertThrows(
        () => {
          new EncryptionContextImpl(api, kdf, params);
        },
        Error,
        "Export only",
      );
    });
  });
});

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
        new TextEncoder().encode("my-secret-message"),
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
        new TextEncoder().encode("my-secret-message"),
      );
      await assertRejects(() =>
        recipient1.seal(
          new TextEncoder().encode("my-secret-message"),
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
        new TextEncoder().encode("my-secret-message"),
      );
      await assertRejects(
        () => recipient1.seal(new TextEncoder().encode("my-secret-message")),
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
        () => sender.export(te.encode("info"), -1),
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
        () => sender.export(te.encode("info"), -1),
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
        () => sender.export(new Uint8Array(8193), 32),
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

  describe("without key info", () => {
    it("should throw Error", async () => {
      const api = await loadSubtleCrypto();
      const suiteId = new Uint8Array(SUITE_ID_HEADER_HPKE);
      suiteId.set(i2Osp(KemId.DhkemP256HkdfSha256, 2), 4);
      suiteId.set(i2Osp(KdfId.HkdfSha256, 2), 6);
      suiteId.set(i2Osp(AeadId.Aes128Gcm, 2), 8);
      const kdf = new HkdfSha256();
      kdf.init(suiteId);
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
//     assertThrows(() => { ec.incrementSeq(ki); }, MessageLimitReachedError, 'Message limit reached');
//   });
// });
