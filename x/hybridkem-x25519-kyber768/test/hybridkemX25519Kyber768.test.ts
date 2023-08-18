// import { assertEquals, assertRejects } from "testing/asserts.ts";
import { assertEquals } from "testing/asserts.ts";
import { afterAll, beforeAll, describe, it } from "testing/bdd.ts";

import type { TestVector } from "../../../test/testVector.ts";

import {
  AeadId,
  Aes128Gcm,
  CipherSuite,
  HkdfSha256,
  KdfId,
  KemId,
  PreSharedKey,
} from "../../../core/mod.ts";
// import { Kyber768 } from "../../../src/kems/pqkemPrimitives/kyber768.ts";
// import { DhkemX25519HkdfSha256 } from "../../../src/kems/dhkemX25519.ts";
import { hexToBytes, testVectorPath } from "../../../test/utils.ts";
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

describe("test-vectors", () => {
  let count: number;
  let testVectors: TestVector[];

  beforeAll(async () => {
    count = 0;
    testVectors = JSON.parse(
      await Deno.readTextFile(testVectorPath() + "/test-vectors.json"),
    );
  });

  afterAll(() => {
    console.log(`passed/total: ${count}/${testVectors.length}`);
  });

  describe("Hybridkem/X25519Kyber768/HkdfSha256/Aes128Gcm", () => {
    it("should work normally", async () => {
      for (const v of testVectors) {
        const suite = new CipherSuite({
          kem: new HybridkemX25519Kyber768(),
          kdf: new HkdfSha256(),
          aead: new Aes128Gcm(),
        });

        const ikmR = hexToBytes(v.ikmR);
        const pkRm = hexToBytes(v.pkRm);
        const skRm = hexToBytes(v.skRm);
        // const sharedSecret = hexToBytes(v.shared_secret);

        // deriveKeyPair
        const rkp = await suite.kem.deriveKeyPair(ikmR);
        const pkR = new Uint8Array(
          await suite.kem.serializePublicKey(rkp.publicKey),
        );
        const skR = new Uint8Array(
          await suite.kem.serializePrivateKey(rkp.privateKey),
        );
        assertEquals(skR, skRm);
        assertEquals(pkR, pkRm);

        // create EncryptionContext
        const info = hexToBytes(v.info);
        let psk: PreSharedKey | undefined = undefined;
        if (v.psk !== undefined && v.psk_id !== undefined) {
          psk = { id: new ArrayBuffer(0), key: new ArrayBuffer(0) };
          psk.key = hexToBytes(v.psk);
          psk.id = hexToBytes(v.psk_id);
        }
        const enc = hexToBytes(v.enc);
        const ier = hexToBytes(v.ier);

        const sender = await suite.createSenderContext({
          info: info,
          psk: psk,
          recipientPublicKey: rkp.publicKey,
          // senderKey: skp,
          ekm: ier, // FOR DEBUGGING/TESTING PURPOSES ONLY.
        });
        assertEquals(new Uint8Array(sender.enc), enc);

        const recipient = await suite.createRecipientContext({
          info: info,
          psk: psk,
          recipientKey: rkp,
          enc: sender.enc,
          // senderPublicKey: pks,
        });

        // seal and open
        if (v.aead_id !== 0xFFFF) {
          for (const ve of v.encryptions) {
            const pt = hexToBytes(ve.pt);
            const aad = hexToBytes(ve.aad);
            const ct = hexToBytes(ve.ct);

            const sealed = await sender.seal(pt, aad);
            const opened = await recipient.open(sealed, aad);
            assertEquals(new Uint8Array(sealed), ct);
            assertEquals(new Uint8Array(opened), pt);
          }
        }

        // export
        for (const ve of v.exports) {
          const ec = ve.exporter_context.length === 0
            ? new ArrayBuffer(0)
            : hexToBytes(ve.exporter_context);
          const ev = hexToBytes(ve.exported_value);

          let exported = await sender.export(ec, ve.L);
          assertEquals(new Uint8Array(exported), ev);
          exported = await recipient.export(ec, ve.L);
          assertEquals(new Uint8Array(exported), ev);
        }
        count++;
      }
    });
  });
});
