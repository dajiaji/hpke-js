import { assertEquals } from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

import type { PreSharedKey } from "@hpke/core";

import { Aes128Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";

import { hexToBytes } from "../../../core/test/utils.ts";
import { HybridkemX25519Kyber768 } from "../mod.ts";
import { TEST_VECTORS } from "./testVectors.ts";

describe("test-vectors", () => {
  let count: number;

  beforeAll(() => {
    count = 0;
  });

  afterAll(() => {
    console.log(`passed/total: ${count}/${TEST_VECTORS.length}`);
  });

  describe("Hybridkem/X25519Kyber768/HkdfSha256/Aes128Gcm", () => {
    it("should work normally", async () => {
      for (const v of TEST_VECTORS) {
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
