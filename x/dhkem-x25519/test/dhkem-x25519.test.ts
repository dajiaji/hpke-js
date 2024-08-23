import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  AeadId,
  Aes128Gcm,
  CipherSuite,
  ExportOnly,
  HkdfSha256,
  KdfId,
  KemId,
} from "@hpke/core";

import { loadCrypto } from "../../core/test/utils.ts";
import { DhkemX25519HkdfSha256 } from "../mod.ts";

describe("DhkemX25519HkdfSha256", () => {
  describe("with valid parameters", () => {
    it("should have a correct KEM object", () => {
      // assert
      const kem = new DhkemX25519HkdfSha256();
      assertEquals(typeof kem, "object");
      assertEquals(kem.id, KemId.DhkemX25519HkdfSha256);
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 32);
      assertEquals(kem.publicKeySize, 32);
      assertEquals(kem.privateKeySize, 32);
    });
  });
});

describe("generateKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      // assert
      const kem = new DhkemX25519HkdfSha256();
      const kp = await kem.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "X25519");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "X25519");
      assertEquals(kp.publicKey.usages.length, 0);
      // assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "X25519");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "X25519");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });
});

describe("deriveKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      const cryptoApi = await loadCrypto();

      // assert
      const kem = new DhkemX25519HkdfSha256();
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kem.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "X25519");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "X25519");
      assertEquals(kp.publicKey.usages.length, 0);
      // assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "X25519");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "X25519");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });
});

describe("serialize/deserializePublicKey", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemX25519HkdfSha256", async () => {
      // assert
      const kem = new DhkemX25519HkdfSha256();
      const kp = await kem.generateKeyPair();
      const bPubKey = await kem.serializePublicKey(kp.publicKey);
      const pubKey = await kem.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "X25519");
      // assertEquals(pubKey.algorithm.namedCurve, "X25519");
      assertEquals(pubKey.usages.length, 0);
      // assertEquals(pubKey.usages[0], "deriveBits");
    });
  });
});

describe("importKey", () => {
  describe("with valid parameters", () => {
    it("should return a valid private key for DhkemX25519HkdfSha256 from raw key", async () => {
      const kem = new DhkemX25519HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);
      const privKey = await kem.importKey("raw", rawKey, false);

      // assert
      assertEquals(privKey.usages.length, 1);
      assertEquals(privKey.usages[0], "deriveBits");
    });

    it("should return a valid public key for DhkemX25519HkdfSha256 from raw key", async () => {
      const kem = new DhkemX25519HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);
      const privKey = await kem.importKey("raw", rawKey, true);

      // assert
      assertEquals(privKey.usages.length, 0);
      // assertEquals(privKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw DeserializeError with invalid DhkemX25519HkdfSha256 private key", async () => {
      const kem = new DhkemX25519HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      cryptoApi.getRandomValues(rawKey);

      // assert
      await assertRejects(
        () => kem.importKey("raw", rawKey, false),
        Error,
      );
    });

    it("should throw DeserializeError with invalid DhkemX25519HkdfSha256 public key", async () => {
      const kem = new DhkemX25519HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      cryptoApi.getRandomValues(rawKey);

      // assert
      await assertRejects(
        () => kem.importKey("raw", rawKey, true),
        Error,
      );
    });
  });
});

describe("CipherSuite", () => {
  describe("constructor with DhkemX25519HkdfSha256", () => {
    it("should have a correct ciphersuite", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: new DhkemX25519HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new ExportOnly(),
      });
      assertEquals(suite.kem.secretSize, 32);
      assertEquals(suite.kem.encSize, 32);
      assertEquals(suite.kem.publicKeySize, 32);
      assertEquals(suite.kem.privateKeySize, 32);

      // assert
      assertEquals(suite.kem.id, KemId.DhkemX25519HkdfSha256);
      assertEquals(suite.kem.id, 0x0020);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.ExportOnly);
      assertEquals(suite.aead.id, 0xFFFF);
    });
  });

  describe("A README example of DhkemX25519HkdfSha256", () => {
    it("should work normally", async () => {
      // setup
      const kem = new DhkemX25519HkdfSha256();
      const suite = new CipherSuite({
        kem: kem,
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });

      const rkp = await suite.kem.generateKeyPair();

      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });

      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, kem.encSize);
      assertEquals(sender.enc.byteLength, kem.publicKeySize);

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
});
