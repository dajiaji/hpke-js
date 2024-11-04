import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemXWing } from "@hpke/hybridkem-x-wing";

async function doHpke() {
  const suite = new CipherSuite({
    kem: new HybridkemXWing(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

  // A sender encrypts a message.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // A recipient decrypts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });
  const pt = await recipient.open(ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (e) {
  console.log("Error: ", e.message);
}
