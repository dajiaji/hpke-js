import { assertEquals, assertNotEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  ExportOnly,
  HkdfSha256,
} from "../mod.ts";

const te = new TextEncoder();
const PSK = {
  id: te.encode("Ennyn Durin aran Moria"),
  key: te.encode("jugemujugemugokounosurikerekaija"),
};

describe("key schedule", () => {
  it("should derive matching ExportOnly contexts in the Base and PSK modes", async () => {
    const suite = new CipherSuite({
      kem: new DhkemP256HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new ExportOnly(),
    });
    const rkp = await suite.kem.generateKeyPair();
    const info = te.encode("key schedule test");
    const exported: Uint8Array[] = [];
    for (const psk of [undefined, PSK, undefined]) {
      const sender = await suite.createSenderContext({
        recipientPublicKey: rkp.publicKey,
        info,
        psk,
      });
      const recipient = await suite.createRecipientContext({
        recipientKey: rkp,
        enc: sender.enc,
        info,
        psk,
      });
      const s = new Uint8Array(await sender.export(te.encode("ctx"), 32));
      assertEquals(
        s,
        new Uint8Array(await recipient.export(te.encode("ctx"), 32)),
      );
      await assertRejects(() => sender.seal(te.encode("hello")));
      exported.push(s);
    }
    assertNotEquals(exported[0], exported[1]);
  });

  it("should derive the same keys in any order of Base and PSK modes", async () => {
    const suite = new CipherSuite({
      kem: new DhkemP256HkdfSha256(),
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
    const rkp = await suite.kem.generateKeyPair();
    const pt = te.encode("hello");
    // Interleave modes on the same suite, including concurrent setups, so
    // that the cached psk_id_hash for the empty psk_id is never misused.
    const runs = await Promise.all(
      [PSK, undefined, PSK, undefined].map(async (psk) => {
        const { ct, enc } = await suite.seal(
          { recipientPublicKey: rkp.publicKey, psk },
          pt,
        );
        return { ct, enc, psk };
      }),
    );
    for (const { ct, enc, psk } of runs) {
      assertEquals(
        new Uint8Array(await suite.open({ recipientKey: rkp, enc, psk }, ct)),
        pt,
      );
      // Opening in the other mode must fail.
      await assertRejects(() =>
        suite.open(
          { recipientKey: rkp, enc, psk: psk === undefined ? PSK : undefined },
          ct,
        )
      );
    }
  });

  it("should keep the sequence of multiple messages with the derived base nonce", async () => {
    const suite = new CipherSuite({
      kem: new DhkemP256HkdfSha256(),
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
    for (let i = 0; i < 3; i++) {
      const pt = te.encode(`message ${i}`);
      assertEquals(
        new Uint8Array(await recipient.open(await sender.seal(pt))),
        pt,
      );
    }
  });
});
