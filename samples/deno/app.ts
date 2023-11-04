// import {
//   Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256,
// } from "https://deno.land/x/hpke@1.2.4/core/mod.ts";
// import { DhkemX25519HkdfSha256 } from "https://deno.land/x/hpke@1.2.4/x/dhkem-x25519/mod.ts";
import {
  AeadId,
  CipherSuite,
  KdfId,
  KemId,
} from "https://deno.land/x/hpke@1.2.4/mod.ts";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Chacha20Poly1305,
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
