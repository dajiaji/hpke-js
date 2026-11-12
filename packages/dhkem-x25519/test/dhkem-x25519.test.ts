import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { loadCrypto } from "@hpke/common";
import {
  AeadId,
  Aes128Gcm,
  CipherSuite,
  ExportOnly,
  HkdfSha256,
  InvalidParamError,
  KdfId,
  KemId,
} from "@hpke/core";

import { DhkemX25519HkdfSha256 } from "../mod.ts";

function bytesToBase64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/g)!.map((byte) => parseInt(byte, 16)));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

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

    it("should match RFC 9180 A.1.1 for a fixed IKM", async () => {
      const kem = new DhkemX25519HkdfSha256();
      const ikm = hexToBytes(
        "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234",
      );
      const first = await kem.deriveKeyPair(ikm);
      const second = await kem.deriveKeyPair(ikm);

      assertEquals(
        new Uint8Array(await kem.serializePrivateKey(first.privateKey)),
        new Uint8Array(await kem.serializePrivateKey(second.privateKey)),
      );
      assertEquals(
        new Uint8Array(await kem.serializePublicKey(first.publicKey)),
        new Uint8Array(await kem.serializePublicKey(second.publicKey)),
      );
      assertEquals(
        new Uint8Array(await kem.serializePrivateKey(first.privateKey)),
        hexToBytes(
          "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736",
        ),
      );
      assertEquals(
        new Uint8Array(await kem.serializePublicKey(first.publicKey)),
        hexToBytes(
          "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
        ),
      );
    });

    it("should accept an IKM at the HPKE input limit", async () => {
      const kem = new DhkemX25519HkdfSha256();
      const keyPair = await kem.deriveKeyPair(new Uint8Array(8192));
      assertEquals(keyPair.privateKey.type, "private");
    });
  });

  describe("with invalid parameters", () => {
    it("should reject an IKM larger than the HPKE input limit", async () => {
      const kem = new DhkemX25519HkdfSha256();
      await assertRejects(
        () => kem.deriveKeyPair(new Uint8Array(8193)),
        InvalidParamError,
      );
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
      const privKey = await kem.importKey(
        "raw",
        rawKey.buffer as ArrayBuffer,
        false,
      );

      // assert
      assertEquals(privKey.usages.length, 1);
      assertEquals(privKey.usages[0], "deriveBits");
    });

    it("should return a valid public key for DhkemX25519HkdfSha256 from raw key", async () => {
      const kem = new DhkemX25519HkdfSha256();

      const cryptoApi = await loadCrypto();
      const rawKey = new Uint8Array(32);
      cryptoApi.getRandomValues(rawKey);
      const privKey = await kem.importKey(
        "raw",
        rawKey.buffer as ArrayBuffer,
        true,
      );

      // assert
      assertEquals(privKey.usages.length, 0);
      // assertEquals(privKey.usages[0], "deriveBits");
    });

    it("should import matching public and private JWKs", async () => {
      const kem = new DhkemX25519HkdfSha256();
      const kp = await kem.generateKeyPair();
      const sk = new Uint8Array(await kem.serializePrivateKey(kp.privateKey));
      const pk = new Uint8Array(await kem.serializePublicKey(kp.publicKey));
      const importedSk = await kem.importKey("jwk", {
        kty: "OKP",
        crv: "X25519",
        d: bytesToBase64Url(sk),
      }, false);
      const importedPk = await kem.importKey("jwk", {
        kty: "OKP",
        crv: "X25519",
        x: bytesToBase64Url(pk),
      }, true);

      assertEquals(
        new Uint8Array(await kem.serializePrivateKey(importedSk)),
        sk,
      );
      assertEquals(
        new Uint8Array(await kem.serializePublicKey(importedPk)),
        pk,
      );
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
        () => kem.importKey("raw", rawKey.buffer as ArrayBuffer, false),
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
        () => kem.importKey("raw", rawKey.buffer as ArrayBuffer, true),
        Error,
      );
    });

    it("should reject JWKs for another curve or key type", async () => {
      const kem = new DhkemX25519HkdfSha256();
      await assertRejects(
        () =>
          kem.importKey(
            "jwk",
            { kty: "EC", crv: "X25519", x: "A".repeat(43) },
            true,
          ),
        Error,
      );
      await assertRejects(
        () => kem.importKey("jwk", { kty: "OKP", crv: "X448", x: "AA" }, true),
        Error,
      );
    });
  });
});

describe("encap/decap", () => {
  it("should derive the same secret for authenticated encapsulation", async () => {
    const kem = new DhkemX25519HkdfSha256();
    const recipient = await kem.generateKeyPair();
    const sender = await kem.generateKeyPair();
    const encapsulated = await kem.encap({
      recipientPublicKey: recipient.publicKey,
      senderKey: sender,
    });
    const recovered = await kem.decap({
      recipientKey: recipient,
      enc: encapsulated.enc,
      senderPublicKey: sender.publicKey,
    });

    assertEquals(
      new Uint8Array(recovered),
      new Uint8Array(encapsulated.sharedSecret),
    );

    const mismatched = await kem.decap({
      recipientKey: recipient,
      enc: encapsulated.enc,
      senderPublicKey: (await kem.generateKeyPair()).publicKey,
    });
    assertEquals(
      bytesEqual(
        new Uint8Array(mismatched),
        new Uint8Array(encapsulated.sharedSecret),
      ),
      false,
    );
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
        new TextEncoder().encode("my-secret-message").buffer as ArrayBuffer,
      );

      // decrypt
      const pt = await recipient.open(ct);

      // assert
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });
});
