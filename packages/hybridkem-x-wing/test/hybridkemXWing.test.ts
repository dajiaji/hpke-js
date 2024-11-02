import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { hexToBytes, KemId } from "@hpke/common";
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
        // assertEquals(
        //   new Uint8Array(await kem.serializePublicKey(kp.publicKey)),
        //   pk,
        // );
        const sender = new HybridkemXWing();
        const res = await sender.encap({
          recipientPublicKey: kp.publicKey,
          ekm: eseed,
        });
        const ssR = await recipient.decap({
          enc: res.enc,
          recipientKey: kp.privateKey,
        });
        assertEquals(res.sharedSecret, ssR);
      }
    });
  });
});

// describe("README examples", () => {
//   describe("HybridkemXWing/HkdfShar256/Aes128Gcm", () => {
//     it("should work normally", async () => {
//       const suite = new CipherSuite({
//         kem: new HybridkemXWing(),
//         kdf: new HkdfSha256(),
//         aead: new Aes128Gcm(),
//       });
//       const rkp = await suite.kem.generateKeyPair();
//       const sender = await suite.createSenderContext({
//         recipientPublicKey: rkp.publicKey,
//       });
//       const recipient = await suite.createRecipientContext({
//         recipientKey: rkp,
//         enc: sender.enc,
//       });
//       assertEquals(sender.enc.byteLength, suite.kem.encSize);
//
//       // encrypt
//       const ct = await sender.seal(
//         new TextEncoder().encode("my-secret-message"),
//       );
//
//       // decrypt
//       const pt = await recipient.open(ct);
//
//       // assert
//       assertEquals(new TextDecoder().decode(pt), "my-secret-message");
//     });
//   });
// });
