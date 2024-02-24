import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

export const test = async () => {
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });

  // I expected to be able to do:
  // const rkp = await suite.kem.generateKeyPair();
  // instead I needed to do:
  const extractable = true
  const rkp = await window.crypto.subtle.generateKey({
    name: "ECDH",
    namedCurve: "P-256",
  }, extractable, ['deriveBits'])
  
  // A sender encrypts a message.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey
  });
  const ct = await sender.seal(new TextEncoder().encode("✨ hello world! ✨"));
  // A recipient decripts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });
  try {
    const pt = await recipient.open(ct);
    // hello world!
    alert(new TextDecoder().decode(pt));
  } catch (err) {
    alert("failed to decrypt.");
  }
}
