import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { HybridkemX25519Kyber768 } from "@hpke/hybridkem-x25519-kyber768";

async function doHpke() {
  // setup
  const suite = new CipherSuite({
    kem: new HybridkemX25519Kyber768(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
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
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // decrypt
  const pt = await recipient.open(ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (err: unknown) {
  console.log("Error: ", err as Error);
}
