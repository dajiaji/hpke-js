import { AeadId, CipherSuite, KdfId, KemId } from "@hpke/hpke-js";

async function doHpke() {
  // When using "@hpke/hpke-js", you can specify the identifier as follows:
  const suite = new CipherSuite({
    kem: KemId.DhkemX25519HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });
  // When using "@hpke/core" and @hpke/dhkem-x25519, specify the instances as follows:
  // const suite = new CipherSuite({
  //   kem: new DhkemX25519HkdfSha256(),
  //   kdf: new HkdfSha256(),
  //   aead: new Aes128Gcm(),
  // });

  const rkp = await suite.kem.generateKeyPair();

  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });

  // A JWK-formatted recipient public key can also be used.
  // const jwkPkR = {
  //   kty: "EC",
  //   crv: "P-256",
  //   kid: "P-256-01",
  //   x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
  //   y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
  //   key_ops: [],
  // };
  // const pkR = await suite.kem.importKey("jwk", jwkPkR, true);
  // const sender = await suite.createSenderContext({
  //   recipientPublicKey: pkR,
  // });

  // encrypt
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });

  // A JWK-formatted recipient private key can also be used.
  // const jwkSkR = {
  //   kty: "EC",
  //   crv: "P-256",
  //   kid: "P-256-01",
  //   x: "-eZXC6nV-xgthy8zZMCN8pcYSeE2XfWWqckA2fsxHPc",
  //   y: "BGU5soLgsu_y7GN2I3EPUXS9EZ7Sw0qif-V70JtInFI",
  //   d: "kwibx3gas6Kz1V2fyQHKSnr-ybflddSjN0eOnbmLmyo",
  //   key_ops: ["deriveBits"],
  // };
  // const skR = await suite.kem.importKey("jwk", jwkSkR, false);
  // const recipient = await suite.createRecipientContext({
  //   recipientKey: skR,
  //   enc: sender.enc,
  // });

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
