import { expect, test } from "bun:test";

import { CipherSuite } from "hpke-js";

test("bun - normal cases", async () => {
  for (const kem of [0x0010, 0x0011, 0x0012, 0x0020, 0x0021]) {
    for (const kdf of [0x0001, 0x0002, 0x0003]) {
      for (const aead of [0x0001, 0x0002, 0x0003]) {
        try {
          const suite = new CipherSuite({ kem: kem, kdf: kdf, aead: aead });
          const rkp = await suite.kem.generateKeyPair();
          const sender = await suite.createSenderContext({
            recipientPublicKey: rkp.publicKey,
          });
          const recipient = await suite.createRecipientContext({
            recipientKey: rkp,
            enc: sender.enc,
          });
          const ct = await sender.seal(
            new TextEncoder().encode("hello world!"),
          );
          const pt = await recipient.open(ct);
          expect(new TextDecoder().decode(pt)).toBe("hello world!");
        } catch (e: unknown) {
          expect().fail("ng: " + (e as Error).message);
        }
      }
    }
  }
});
