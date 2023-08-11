import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// const { KemId, KdfId, AeadId, CipherSuite } = require("@hpke/core");
// import { KemId, KdfId, AeadId, CipherSuite } from "hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
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
  try {
    const pt = await recipient.open(ct);
    console.log("decrypted: ", new TextDecoder().decode(pt));
  } catch (e) {
    console.log("failed to decrypt:", e.message);
  }
}

doHpke();
