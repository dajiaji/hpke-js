import { Aes128Gcm, createJoseHpke3, createJoseHpke3Ke } from "@hpke/jose";

async function doJoseEncrypt0() {
  const enc0 = createJoseHpke3();
  const rkp = await enc0.generateKemKeyPair();

  // A sender encrypts a message into a compact JWE.
  const jwe = await enc0.seal(
    rkp.publicKey,
    new TextEncoder().encode("Hello world!"),
  );

  // A recipient decrypts it.
  const pt = await enc0.open(rkp, jwe);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

async function doJoseEncrypt() {
  const enc = createJoseHpke3Ke(new Aes128Gcm());
  const rkp = await enc.generateKemKeyPair();

  // A sender encrypts a message into a JSON JWE.
  const jwe = await enc.seal(
    [{ recipientPublicKey: rkp.publicKey }],
    new TextEncoder().encode("Hello world!"),
  );

  // A recipient decrypts it.
  const pt = await enc.open(rkp, jwe);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  await doJoseEncrypt0();
  await doJoseEncrypt();
} catch (e) {
  console.log("Error:", e.message);
}
