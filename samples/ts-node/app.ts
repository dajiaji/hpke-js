import * as util from "util";
import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/core";
// import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

async function doHpke() {
  const suite: CipherSuite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });

  // encrypt
  const ct = await sender.seal(
    new util.TextEncoder().encode("my-secret-message"),
  );

  // decrypt
  const pt = await recipient.open(ct);

  // new TextDecoder().decode(pt) === "my-secret-message"
  console.log("decrypted: ", new util.TextDecoder().decode(pt));
}

doHpke();
