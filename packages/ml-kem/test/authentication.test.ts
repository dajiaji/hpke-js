import { it } from "@std/testing/bdd";
import { assertEquals, assertRejects } from "@std/assert";
import {
  Aes128Gcm,
  CipherSuite,
  HkdfSha256,
  NotSupportedError,
} from "@hpke/core";
import { MlKem1024, MlKem512, MlKem768 } from "../mod.ts";

for (const Kem of [MlKem512, MlKem768, MlKem1024]) {
  it(`${Kem.name}: rejects authentication and preserves Base/PSK`, async () => {
    const kem = new Kem();
    const suite = new CipherSuite({
      kem,
      kdf: new HkdfSha256(),
      aead: new Aes128Gcm(),
    });
    const recipient = await kem.generateKeyPair();
    const sender = await kem.generateKeyPair();
    const plaintext = new Uint8Array([1, 2, 3]).buffer;
    const psk = { key: new Uint8Array(32).fill(1), id: new Uint8Array([1]) };
    for (const secret of [undefined, psk]) {
      const sealed = await suite.seal({
        recipientPublicKey: recipient.publicKey,
        psk: secret,
      }, plaintext);
      assertEquals(
        await suite.open({
          recipientKey: recipient,
          enc: sealed.enc,
          psk: secret,
        }, sealed.ct),
        plaintext,
      );
      const senderParams = {
        recipientPublicKey: recipient.publicKey,
        senderKey: sender,
        psk: secret,
      };
      const recipientParams = {
        recipientKey: recipient,
        enc: sealed.enc,
        senderPublicKey: sender.publicKey,
        psk: secret,
      };
      await assertRejects(
        () => suite.createSenderContext(senderParams),
        NotSupportedError,
      );
      await assertRejects(
        () => suite.createRecipientContext(recipientParams),
        NotSupportedError,
      );
      await assertRejects(
        () => suite.seal(senderParams, plaintext),
        NotSupportedError,
      );
      await assertRejects(
        () => suite.open(recipientParams, sealed.ct),
        NotSupportedError,
      );
      await assertRejects(() => kem.encap(senderParams), NotSupportedError);
      await assertRejects(() => kem.decap(recipientParams), NotSupportedError);
    }
  });
}
