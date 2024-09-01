import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  AeadId,
  Aes128Gcm,
  CipherSuite,
  HkdfSha256,
  KdfId,
  KemId,
} from "@hpke/core";
import { HybridkemX25519Kyber768 } from "../mod.ts";

describe("constructor", () => {
  describe("with HybridkemX25519Kyber768", () => {
    it("should have a correct ciphersuite", () => {
      const suite: CipherSuite = new CipherSuite({
        kem: new HybridkemX25519Kyber768(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });
      assertEquals(suite.kem.secretSize, 64);
      assertEquals(suite.kem.encSize, 1120);
      assertEquals(suite.kem.publicKeySize, 1216);
      assertEquals(suite.kem.privateKeySize, 2432);

      // assert
      assertEquals(suite.kem.id, KemId.HybridkemX25519Kyber768);
      assertEquals(suite.kem.id, 0x0030);
      assertEquals(suite.kdf.id, KdfId.HkdfSha256);
      assertEquals(suite.kdf.id, 0x0001);
      assertEquals(suite.aead.id, AeadId.Aes128Gcm);
      assertEquals(suite.aead.id, 0x0001);
    });
  });
});

describe("README examples", () => {
  describe("HybridkemX25519Kyber768/HkdfShar256/Aes128Gcm", () => {
    it("should work normally", async () => {
      const suite = new CipherSuite({
        kem: new HybridkemX25519Kyber768(),
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
      assertEquals(sender.enc.byteLength, suite.kem.encSize);

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
