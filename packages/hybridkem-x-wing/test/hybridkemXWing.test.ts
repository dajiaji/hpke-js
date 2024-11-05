import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { hexToBytes, loadCrypto } from "@hpke/common";
import { Aes128Gcm, CipherSuite, HkdfSha256, KemId } from "@hpke/core";
import { HybridkemXWing } from "../mod.ts";
import { TEST_VECTORS } from "./testVectors.ts";

describe("HybridkemXWing", () => {
  describe("constructor", () => {
    it("should have a correct ciphersuite", () => {
      const kem = new HybridkemXWing();
      assertEquals(kem.secretSize, 32);
      assertEquals(kem.encSize, 1120);
      assertEquals(kem.publicKeySize, 1216);
      assertEquals(kem.privateKeySize, 32);
      assertEquals(kem.id, KemId.HybridkemXWing);
      assertEquals(kem.id, 0x647a);
    });
  });

  describe("official test vectors", () => {
    it("should match the results", async () => {
      for (const v of TEST_VECTORS) {
        const seed = hexToBytes(v.seed);
        const sk = hexToBytes(v.sk);
        const pk = hexToBytes(v.pk);
        const eseed = hexToBytes(v.eseed);
        const ct = hexToBytes(v.ct);
        const ss = hexToBytes(v.ss);
        assertEquals(seed.length, 32);
        assertEquals(sk.length, 32);
        assertEquals(pk.length, 1216);
        assertEquals(eseed.length, 64);
        assertEquals(ct.length, 1120);
        assertEquals(ss.length, 32);

        const recipient = new HybridkemXWing();
        const kp = await recipient.generateKeyPairDerand(seed);
        assertEquals(
          (await recipient.serializePublicKey(kp.publicKey)).byteLength,
          1216,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePrivateKey(kp.privateKey)),
          sk,
        );
        assertEquals(
          new Uint8Array(await recipient.serializePublicKey(kp.publicKey)),
          pk,
        );
        const sender = new HybridkemXWing();
        const res = await sender.encap({
          recipientPublicKey: kp.publicKey,
          ekm: eseed,
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.enc.byteLength, 1120);
        assertEquals(res.sharedSecret.byteLength, 32);
        assertEquals(res.enc, ct);
        assertEquals(res.sharedSecret, ssR);
        assertEquals(res.sharedSecret, ss);
        // assertEquals(ssR, ss);
      }
    });
  });
});

describe("README examples", () => {
  describe("HybridkemXWing/HkdfShar256/Aes128Gcm", () => {
    it("should work normally with generateKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new HybridkemXWing(),
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
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });

    it("should work normally with deriveKeyPair", async () => {
      const suite = new CipherSuite({
        kem: new HybridkemXWing(),
        kdf: new HkdfSha256(),
        aead: new Aes128Gcm(),
      });
      const cryptoApi = await loadCrypto();
      const ikm = new Uint8Array(32);
      cryptoApi.getRandomValues(ikm);
      const rkp = await suite.kem.deriveKeyPair(ikm.buffer);
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
      });
      assertEquals(sender.enc.byteLength, suite.kem.encSize);
      const ct = await sender.seal(
        new TextEncoder().encode("my-secret-message"),
      );
      const pt = await recipient.open(ct);
      assertEquals(new TextDecoder().decode(pt), "my-secret-message");
    });
  });
});
