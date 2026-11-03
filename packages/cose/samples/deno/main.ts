import { Aes128Gcm, createHpke3, createHpke3Ke } from "@hpke/cose";

async function doCoseEncrypt0() {
  // setup
  const enc0 = createHpke3();
  const rkp = await enc0.suite.kem.generateKeyPair();

  // encrypt
  const ct = await enc0.seal(
    rkp.publicKey,
    new TextEncoder().encode("Hello world!"),
  );

  // decrypt
  const pt = await enc0.open(rkp, ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

async function doCoseEncrypt() {
  // setup
  const enc = createHpke3Ke(new Aes128Gcm());
  const rkp = await enc.generateKemKeyPair();

  // encrypt
  const ct = await enc.seal(
    [{ recipientPublicKey: rkp.publicKey }],
    new TextEncoder().encode("Hello world!"),
  );

  // decrypt
  const pt = await enc.open(rkp, ct);

  // Hello world!
  console.log(new TextDecoder().decode(pt));
}

try {
  await doCoseEncrypt0();
  await doCoseEncrypt();
} catch (err: unknown) {
  console.log("Error: ", err as Error);
}
