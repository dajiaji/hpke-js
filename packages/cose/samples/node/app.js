import { Aes128Gcm, createHpke3, createHpke3Ke } from "@hpke/cose";

async function doCoseEncrypt0() {
  const enc0 = createHpke3();
  const rkp = await enc0.suite.kem.generateKeyPair();

  // A sender encrypts a message into a COSE_Encrypt0 structure.
  const ct = await enc0.seal(
    rkp.publicKey,
    new TextEncoder().encode("Hello world!"),
  );

  // A recipient decrypts it.
  const pt = await enc0.open(rkp, ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

async function doCoseEncrypt() {
  const enc = createHpke3Ke(new Aes128Gcm());
  const rkp = await enc.generateKemKeyPair();

  // A sender encrypts a message into a COSE_Encrypt structure.
  const ct = await enc.seal(
    [{ recipientPublicKey: rkp.publicKey }],
    new TextEncoder().encode("Hello world!"),
  );

  // A recipient decrypts it.
  const pt = await enc.open(rkp, ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  await doCoseEncrypt0();
  await doCoseEncrypt();
} catch (e) {
  console.log("Error:", e.message);
}
