import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { hexToBytes, loadCrypto } from "@hpke/common";
import {
  AeadId,
  Aes128Gcm,
  CipherSuite,
  DeserializeError,
  DhkemP256HkdfSha256,
  ExportOnly,
  HkdfSha256,
  KdfId,
  KemId,
  SerializeError,
} from "@hpke/core";

import { DhkemSecp256k1HkdfSha256 } from "../mod.ts";

describe("constructor", () => {
  describe("with valid parameters", () => {
    it("should have a correct KEM object", () => {
      // assert
      const kem = new DhkemSecp256k1HkdfSha256();
      assertEquals(typeof kem, "object");
      assertEquals(kem.id, KemId.DhkemSecp256k1HkdfSha256);
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 33);
      assertEquals(kem.publicKeySize, 33);
      assertEquals(kem.privateKeySize, 32);
    });
  });
});

describe("generateKeyPair", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance", async () => {
      // assert
      const kem = new DhkemSecp256k1HkdfSha256();
      const kp = await kem.generateKeyPair();
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.publicKey.usages.length, 0);
      // assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "secp256k1");
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
      const kem = new DhkemSecp256k1HkdfSha256();
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const kp = await kem.deriveKeyPair(ikm.buffer);
      assertEquals(kp.publicKey.type, "public");
      assertEquals(kp.publicKey.extractable, true);
      assertEquals(kp.publicKey.algorithm.name, "ECDH");
      // assertEquals(kp.publicKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.publicKey.usages.length, 0);
      // assertEquals(kp.publicKey.usages[0], "deriveBits");
      assertEquals(kp.privateKey.type, "private");
      assertEquals(kp.privateKey.extractable, true);
      assertEquals(kp.privateKey.algorithm.name, "ECDH");
      // assertEquals(kp.privateKey.algorithm.namedCurve, "secp256k1");
      assertEquals(kp.privateKey.usages.length, 1);
      assertEquals(kp.privateKey.usages[0], "deriveBits");
    });
  });
});

describe("serialize/deserializePublicKey", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemSecp256k1HkdfSha256", async () => {
      // assert
      const kem = new DhkemSecp256k1HkdfSha256();
      const kp = await kem.generateKeyPair();
      const bPubKey = await kem.serializePublicKey(kp.publicKey);
      const pubKey = await kem.deserializePublicKey(bPubKey);
      assertEquals(pubKey.type, "public");
      assertEquals(pubKey.extractable, true);
      assertEquals(pubKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "secp256k1");
      assertEquals(pubKey.usages.length, 0);
      // assertEquals(pubKey.usages[0], "deriveBits");
    });
  });
  describe("with invalid parameters", () => {
    it("should throw SerializeError on DhkemSecp256k1HkdfSha256.serializePublicKey with a public key for DhkemP256HkdfSha256", async () => {
      // assert
      const ctx = new DhkemP256HkdfSha256();
      const kp = await ctx.generateKeyPair();
      const kemContext = new DhkemSecp256k1HkdfSha256();
      await assertRejects(
        () => kemContext.serializePublicKey(kp.publicKey),
        SerializeError,
      );
    });

    it("should throw DeserializeError on DhkemP256HkdfSha256.deserializePublicKey with invalid length key", async () => {
      // assert
      const kemContext = new DhkemSecp256k1HkdfSha256();
      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33 - 1);
      cryptoApi.getRandomValues(rawKey);
      await assertRejects(
        () => kemContext.deserializePublicKey(rawKey.buffer),
        DeserializeError,
      );
    });
  });
});

describe("serialize/deserializePrivateKey", () => {
  describe("with valid parameters", () => {
    it("should return a proper instance with DhkemSecp256k1HkdfSha256", async () => {
      // assert
      const kemContext = new DhkemSecp256k1HkdfSha256();
      const kp = await kemContext.generateKeyPair();
      const bPrivKey = await kemContext.serializePrivateKey(kp.privateKey);
      const privKey = await kemContext.deserializePrivateKey(bPrivKey);
      assertEquals(privKey.type, "private");
      assertEquals(privKey.extractable, true);
      assertEquals(privKey.algorithm.name, "ECDH");
      // assertEquals(pubKey.algorithm.namedCurve, "secp256k1");
      assertEquals(privKey.usages.length, 1);
      assertEquals(privKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw SerializeError on DhkemSecp256k1HkdfSha256.serializePrivateKey with a private key for DhkemP256HkdfSha256", async () => {
      // assert
      const ctx = new DhkemP256HkdfSha256();
      const kp = await ctx.generateKeyPair();
      const kemContext = new DhkemSecp256k1HkdfSha256();
      await assertRejects(
        () => kemContext.serializePrivateKey(kp.privateKey),
        SerializeError,
      );
    });
    it("should throw DeserializeError on DhkemSecp256k1HkdfSha256.deserializePrivateKey with invalid length key", async () => {
      // assert
      const kemContext = new DhkemSecp256k1HkdfSha256();
      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      cryptoApi.getRandomValues(rawKey);
      await assertRejects(
        () => kemContext.deserializePrivateKey(rawKey.buffer as ArrayBuffer),
        DeserializeError,
      );
    });
  });
});

describe("importKey", () => {
  describe("with valid parameters", () => {
    it("should return a valid private key for DhkemSecp256k1HkdfSha256 from raw key", async () => {
      const kem = new DhkemSecp256k1HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);
      const privKey = await kem.importKey(
        "raw",
        rawKey.buffer as ArrayBuffer,
        false,
      );

      // assert
      assertEquals(privKey.usages.length, 1);
      assertEquals(privKey.usages[0], "deriveBits");
    });

    it("should return a valid public key for DhkemSecp256k1HkdfSha256 from raw key", async () => {
      const kem = new DhkemSecp256k1HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      cryptoApi.getRandomValues(rawKey);
      rawKey[0] = hexToBytes("04")[0];
      const privKey = await kem.importKey(
        "raw",
        rawKey.buffer as ArrayBuffer,
        true,
      );

      // assert
      assertEquals(privKey.usages.length, 0);
      // assertEquals(privKey.usages[0], "deriveBits");
    });
  });

  describe("with invalid parameters", () => {
    it("should throw DeserializeError with invalid DhkemSecp256k1HkdfSha256 private key", async () => {
      const kem = new DhkemSecp256k1HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(33);
      cryptoApi.getRandomValues(rawKey);

      // assert
      await assertRejects(
        () => kem.importKey("raw", rawKey.buffer as ArrayBuffer, false),
        Error,
      );
    });

    it("should throw DeserializeError with invalid DhkemSecp256k1HkdfSha256 public key", async () => {
      const kem = new DhkemSecp256k1HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);

      // assert
      await assertRejects(
        () => kem.importKey("raw", rawKey.buffer as ArrayBuffer, true),
        Error,
      );
    });
  });
});

describe("CipherSuite", () => {
  describe("constructor with DhkemSecp256k1HkdfSha256", () => {
    it("should have a correct ciphersuite", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: new DhkemSecp256k1HkdfSha256(),
        kdf: new HkdfSha256(),
        aead: new ExportOnly(),
      });
      assertEquals(suite.kem.secretSize, 32);
      assertEquals(suite.kem.encSize, 33);
      assertEquals(suite.kem.publicKeySize, 33);
      assertEquals(suite.kem.privateKeySize, 32);

      // assert
      assertEquals(suite.kem.id, KemId.DhkemSecp256k1HkdfSha256);
      assertEquals(suite.kem.id, 0x0013);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.ExportOnly);
      assertEquals(suite.aead.id, 0xFFFF);
    });
  });

  describe("A README example of DhkemSecp256k1HkdfSha256", () => {
    it("should work normally", async () => {
      // setup
      const kem = new DhkemSecp256k1HkdfSha256();
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
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });
});
