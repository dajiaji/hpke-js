import { Aes128Gcm, createJoseHpke3, createJoseHpke3Ke } from "@hpke/jose";

async function doJoseEncrypt0() {
  // setup
  const enc0 = createJoseHpke3();
  const rkp = await enc0.suite.kem.generateKeyPair();

  // encrypt
  const jwe = await enc0.seal(
    rkp.publicKey,
    new TextEncoder().encode("Hello world!"),
  );

  // decrypt
  const pt = await enc0.open(rkp, jwe);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

async function doJoseEncrypt() {
  // setup
  const enc = createJoseHpke3Ke(new Aes128Gcm());
  const rkp = await enc.generateKemKeyPair();

  // encrypt
  const jwe = await enc.seal(
    [{ recipientPublicKey: rkp.publicKey }],
    new TextEncoder().encode("Hello world!"),
  );

  // decrypt
  const pt = await enc.open(rkp, jwe);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  await doJoseEncrypt0();
  await doJoseEncrypt();
} catch (err: unknown) {
  console.log("Error: ", err as Error);
}
