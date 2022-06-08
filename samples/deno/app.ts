import { Aead, CipherSuite, Kdf, Kem } from "https://deno.land/x/hpke/mod.ts";

async function doHpke() {
  const suite: CipherSuite = new CipherSuite({
    kem: Kem.DhkemX25519HkdfSha256,
    kdf: Kdf.HkdfSha256,
    aead: Aead.Chacha20Poly1305,
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
  try {
    const pt = await recipient.open(ct);

    // new TextDecoder().decode(pt) === "my-secret-message"
    console.log("decrypted: ", new TextDecoder().decode(pt));
  } catch (_err: unknown) {
    console.log("failed to decrypt.");
  }
}

doHpke();
