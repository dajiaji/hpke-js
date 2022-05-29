const { Kem, Kdf, Aead, CipherSuite } = require("hpke-js");

async function doHpke() {
  const suite = new CipherSuite({
    kem: Kem.DhkemP256HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Aes128Gcm,
  });

  const rkp = await suite.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp,
    enc: sender.enc,
  });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("my-secret-message"));

  // decrypt
  const pt = await recipient.open(ct);

  // new TextDecoder().decode(pt) === "my-secret-message"
  console.log("decrypted: ", new TextDecoder().decode(pt));
}

doHpke();
