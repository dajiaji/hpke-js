import * as util from "util";

import {
  Aes128Gcm,
  CipherSuite,
  DhkemP256HkdfSha256,
  HkdfSha256,
} from "@hpke/core";
// import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

async function doHpke() {
  const suite: CipherSuite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  const rkp = await suite.kem.generateKeyPair();

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
